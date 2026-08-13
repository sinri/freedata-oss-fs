use crate::{
    config::{Credentials, OssConfig},
    tree::ObjectMeta,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use quick_xml::de::from_str;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant, SystemTime},
};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

pub trait ObjectStore: Send + Sync + 'static {
    fn list_all(&self, prefix: &str) -> Result<Vec<ObjectMeta>>;
    fn read_range(
        &self,
        key: &str,
        etag: Option<&str>,
        object_size: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>>;
}

#[derive(Clone)]
pub struct OssClient {
    agent: ureq::Agent,
    endpoint: Url,
    region: String,
    bucket: String,
    path_style: bool,
    credentials: Option<Credentials>,
    max_list_pages: usize,
    max_objects: usize,
    max_list_page_bytes: u64,
    max_total_key_bytes: usize,
    list_timeout: Duration,
    request_gate: Arc<RequestGate>,
}

#[derive(Debug)]
struct RequestGate {
    in_flight: Mutex<usize>,
    available: Condvar,
    maximum: usize,
}

struct RequestPermit<'a> {
    gate: &'a RequestGate,
}

impl RequestGate {
    fn acquire(&self) -> Result<RequestPermit<'_>> {
        let mut in_flight = self
            .in_flight
            .lock()
            .map_err(|_| anyhow!("OSS request concurrency gate is poisoned"))?;
        while *in_flight >= self.maximum {
            in_flight = self
                .available
                .wait(in_flight)
                .map_err(|_| anyhow!("OSS request concurrency gate is poisoned"))?;
        }
        *in_flight += 1;
        Ok(RequestPermit { gate: self })
    }
}

impl Drop for RequestPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.gate.in_flight.lock() {
            *in_flight = in_flight.saturating_sub(1);
            self.gate.available.notify_one();
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListBucketResult {
    #[serde(default)]
    contents: Vec<ListedObject>,
    #[serde(default)]
    is_truncated: bool,
    next_continuation_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedObject {
    key: String,
    size: u64,
    last_modified: String,
    e_tag: String,
}

impl OssClient {
    pub fn new(
        config: &OssConfig,
        bucket: String,
        credentials: Option<Credentials>,
    ) -> Result<Self> {
        let endpoint = Url::parse(&config.endpoint).context("invalid OSS endpoint")?;
        if credentials.is_some() && endpoint.scheme() != "https" {
            bail!("authenticated OSS access requires an https endpoint");
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(60))
            .redirects(0)
            .build();
        Ok(Self {
            agent,
            endpoint,
            region: config.region.clone(),
            bucket,
            path_style: config.path_style,
            credentials,
            max_list_pages: config.max_list_pages,
            max_objects: config.max_objects,
            max_list_page_bytes: config.max_list_page_bytes,
            max_total_key_bytes: config.max_total_key_bytes,
            list_timeout: Duration::from_secs(config.list_timeout_seconds),
            request_gate: Arc::new(RequestGate {
                in_flight: Mutex::new(0),
                available: Condvar::new(),
                maximum: config.max_concurrent_requests,
            }),
        })
    }

    fn request_url(&self, key: Option<&str>, query: &[(String, String)]) -> Result<String> {
        let scheme = self.endpoint.scheme();
        let endpoint_host = self
            .endpoint
            .host_str()
            .context("OSS endpoint has no host")?;
        let host = if self.path_style {
            endpoint_host.to_string()
        } else {
            format!("{}.{}", self.bucket, endpoint_host)
        };
        let port = self
            .endpoint
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        let mut path = String::from("/");
        if self.path_style {
            path.push_str(&uri_encode(&self.bucket, true));
            path.push('/');
        }
        if let Some(key) = key {
            path.push_str(&uri_encode(key, false));
        }
        let canonical_query = canonical_query(query);
        Ok(format!(
            "{scheme}://{host}{port}{path}{}",
            if canonical_query.is_empty() {
                String::new()
            } else {
                format!("?{canonical_query}")
            }
        ))
    }

    fn signed_get(
        &self,
        key: Option<&str>,
        query: &[(String, String)],
        range: Option<(u64, u64)>,
        if_match: Option<&str>,
    ) -> Result<ureq::Response> {
        let url = self.request_url(key, query)?;
        let mut request = self.agent.get(&url);
        if let Some((start, end)) = range {
            request = request.set("Range", &format!("bytes={start}-{end}"));
        }
        if let Some(etag) = if_match {
            if etag
                .chars()
                .any(|character| character.is_control() || matches!(character, '"' | '\\'))
            {
                bail!("OSS returned an invalid ETag");
            }
            request = request.set("If-Match", &format!("\"{etag}\""));
        }
        if let Some(credentials) = &self.credentials {
            let now = Utc::now();
            let mut headers = BTreeMap::from([
                (
                    "x-oss-content-sha256".to_string(),
                    "UNSIGNED-PAYLOAD".to_string(),
                ),
                (
                    "x-oss-date".to_string(),
                    now.format("%Y%m%dT%H%M%SZ").to_string(),
                ),
            ]);
            if let Some(token) = &credentials.session_token {
                headers.insert("x-oss-security-token".into(), token.clone());
            }
            let canonical_uri = format!(
                "/{}/{}",
                self.bucket,
                key.map(|k| uri_encode(k, false)).unwrap_or_default()
            );
            let authorization = sign_v4(
                "GET",
                &canonical_uri,
                &canonical_query(query),
                &headers,
                &[],
                &self.region,
                credentials,
                now,
            );
            for (name, value) in headers {
                request = request.set(&name, &value);
            }
            request = request.set("Authorization", &authorization);
        }
        match request.call() {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(status, response)) => {
                let request_id = response
                    .header("x-oss-request-id")
                    .unwrap_or("unknown")
                    .to_string();
                let mut body = String::new();
                response
                    .into_reader()
                    .take(16 * 1024)
                    .read_to_string(&mut body)
                    .ok();
                bail!(
                    "OSS returned HTTP {status} (request id {}): {}",
                    escape_log_value(&request_id),
                    escape_log_value(&body)
                )
            }
            Err(error) => Err(anyhow!(error).context("OSS request failed")),
        }
    }
}

impl ObjectStore for OssClient {
    fn list_all(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        let mut result = Vec::new();
        let mut continuation: Option<String> = None;
        let mut seen_tokens = HashSet::new();
        let mut total_key_bytes = 0usize;
        let started = Instant::now();
        let mut pages = 0usize;
        loop {
            if started.elapsed() >= self.list_timeout {
                bail!("OSS listing exceeded its total time limit");
            }
            pages += 1;
            if pages > self.max_list_pages {
                bail!("OSS listing exceeded the configured page limit");
            }
            let mut query = vec![
                ("encoding-type".into(), "url".into()),
                ("list-type".into(), "2".into()),
                ("max-keys".into(), "1000".into()),
            ];
            if !prefix.is_empty() {
                query.push(("prefix".into(), prefix.into()));
            }
            if let Some(token) = &continuation {
                query.push(("continuation-token".into(), token.clone()));
            }
            let _permit = self.request_gate.acquire()?;
            let response = self.signed_get(None, &query, None, None)?;
            let mut xml = String::new();
            response
                .into_reader()
                .take(self.max_list_page_bytes + 1)
                .read_to_string(&mut xml)
                .context("failed reading OSS list response")?;
            if xml.len() as u64 > self.max_list_page_bytes {
                bail!("OSS list response exceeded the configured page size limit");
            }
            let page: ListBucketResult =
                from_str(&xml).context("failed parsing OSS ListObjectsV2 XML")?;
            for object in page.contents {
                let key = percent_decode_str(&object.key)
                    .decode_utf8()
                    .context("OSS returned a non-UTF-8 object key")?
                    .into_owned();
                total_key_bytes = total_key_bytes
                    .checked_add(key.len())
                    .context("OSS object key byte count overflow")?;
                if total_key_bytes > self.max_total_key_bytes {
                    bail!("OSS listing exceeded the configured total key byte limit");
                }
                if result.len() >= self.max_objects {
                    bail!("OSS listing exceeded the configured object limit");
                }
                let modified: DateTime<Utc> = object
                    .last_modified
                    .parse()
                    .with_context(|| format!("invalid LastModified for object {key:?}"))?;
                let etag = normalize_etag(&object.e_tag)
                    .with_context(|| format!("invalid ETag for object {key:?}"))?;
                result.push(ObjectMeta {
                    key,
                    size: object.size,
                    modified: SystemTime::from(modified),
                    etag: Some(etag),
                });
            }
            if !page.is_truncated {
                break;
            }
            let encoded_token = page
                .next_continuation_token
                .context("truncated OSS response did not include NextContinuationToken")?;
            continuation = Some(
                percent_decode_str(&encoded_token)
                    .decode_utf8()
                    .context("OSS returned a non-UTF-8 continuation token")?
                    .into_owned(),
            );
            if !seen_tokens.insert(continuation.clone().expect("token was just assigned")) {
                bail!("OSS returned a repeated continuation token");
            }
        }
        Ok(result)
    }

    fn read_range(
        &self,
        key: &str,
        etag: Option<&str>,
        object_size: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(size as u64 - 1)
            .context("read range overflow")?;
        let _permit = self.request_gate.acquire()?;
        let response = self.signed_get(Some(key), &[], Some((offset, end)), etag)?;
        let status = response.status();
        if status != 206 {
            bail!("OSS did not honor byte range for {key:?}: HTTP {status}");
        }
        let content_range = response
            .header("Content-Range")
            .context("OSS range response omitted Content-Range")?;
        validate_content_range(content_range, offset, end, object_size)
            .with_context(|| format!("invalid OSS Content-Range for {key:?}"))?;
        let mut bytes = Vec::with_capacity(size as usize);
        response
            .into_reader()
            .take(size as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed reading OSS object {key:?}"))?;
        if bytes.len() != size as usize {
            bail!(
                "short OSS range response for {key:?}: expected {size} bytes, received {}",
                bytes.len()
            );
        }
        Ok(bytes)
    }
}

fn validate_content_range(value: &str, start: u64, end: u64, total: u64) -> Result<()> {
    let value = value
        .strip_prefix("bytes ")
        .context("Content-Range must use bytes units")?;
    let (range, actual_total) = value.split_once('/').context("malformed Content-Range")?;
    let (actual_start, actual_end) = range.split_once('-').context("malformed byte range")?;
    if actual_start.parse::<u64>()? != start
        || actual_end.parse::<u64>()? != end
        || actual_total.parse::<u64>()? != total
    {
        bail!("Content-Range does not match the indexed object and requested range");
    }
    Ok(())
}

fn escape_log_value(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn normalize_etag(value: &str) -> Result<String> {
    let etag = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .context("ETag must be a quoted entity-tag")?;
    if etag.is_empty()
        || etag
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\'))
    {
        bail!("ETag contains unsafe characters");
    }
    Ok(etag.to_string())
}

fn canonical_query(query: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = query
        .iter()
        .map(|(key, value)| (uri_encode(key, true), uri_encode(value, true)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(value: &str, encode_slash: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && byte == b'/')
        {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn sign_v4(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &BTreeMap<String, String>,
    additional_headers: &[&str],
    region: &str,
    credentials: &Credentials,
    now: DateTime<Utc>,
) -> String {
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name.to_ascii_lowercase(), value.trim()))
        .collect::<String>();
    let mut additional_headers = additional_headers
        .iter()
        .map(|header| header.to_ascii_lowercase())
        .collect::<Vec<_>>();
    additional_headers.sort();
    let additional_headers = additional_headers.join(";");
    let canonical_request = build_canonical_request(
        method,
        canonical_uri,
        canonical_query,
        &canonical_headers,
        &additional_headers,
    );
    let scope = format!("{date}/{region}/oss/aliyun_v4_request");
    let request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("OSS4-HMAC-SHA256\n{timestamp}\n{scope}\n{request_hash}");
    let date_key = hmac_sha256(
        format!("aliyun_v4{}", credentials.access_key_secret).as_bytes(),
        date.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"oss");
    let signing_key = hmac_sha256(&service_key, b"aliyun_v4_request");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    format!(
        "OSS4-HMAC-SHA256 Credential={}/{scope}, AdditionalHeaders={additional_headers}, Signature={signature}",
        credentials.access_key_id,
    )
}

fn build_canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    canonical_headers: &str,
    additional_headers: &str,
) -> String {
    format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{additional_headers}\nUNSIGNED-PAYLOAD"
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OssConfig;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn anonymous_config(endpoint: String) -> OssConfig {
        OssConfig {
            endpoint,
            region: "cn-test".into(),
            bucket_path: "oss://bucket/root".into(),
            path_style: true,
            anonymous: true,
            access_key_id_env: "UNUSED_ID".into(),
            access_key_secret_env: "UNUSED_SECRET".into(),
            session_token_env: "UNUSED_TOKEN".into(),
            max_list_pages: 10_000,
            max_objects: 1_000_000,
            max_list_page_bytes: 8 * 1024 * 1024,
            max_total_key_bytes: 256 * 1024 * 1024,
            list_timeout_seconds: 300,
            max_concurrent_requests: 32,
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn encoding_and_query_order_follow_v4_rules() {
        assert_eq!(uri_encode("目录/a b", false), "%E7%9B%AE%E5%BD%95/a%20b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(
            canonical_query(&[
                ("prefix".into(), "a/b".into()),
                ("max-keys".into(), "20".into())
            ]),
            "max-keys=20&prefix=a%2Fb"
        );
    }

    #[test]
    fn parses_list_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
          <ListBucketResult><IsTruncated>false</IsTruncated><Contents>
          <Key>root%2F%E6%96%87%E4%BB%B6.txt</Key><LastModified>2025-01-02T03:04:05.000Z</LastModified>
          <ETag>&quot;abc&quot;</ETag><Size>12</Size></Contents></ListBucketResult>"#;
        let parsed: ListBucketResult = from_str(xml).unwrap();
        assert_eq!(parsed.contents[0].size, 12);
        assert_eq!(
            percent_decode_str(&parsed.contents[0].key)
                .decode_utf8()
                .unwrap(),
            "root/文件.txt"
        );
    }

    #[test]
    fn v4_canonical_request_matches_aliyun_documented_vector() {
        let headers: BTreeMap<String, String> = BTreeMap::from([
            ("content-disposition".into(), "attachment".into()),
            ("content-length".into(), "3".into()),
            ("content-md5".into(), "ICy5YqxZB1uWSwcVLSNLcA==".into()),
            ("content-type".into(), "text/plain".into()),
            ("x-oss-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
            ("x-oss-date".into(), "20250411T064124Z".into()),
        ]);
        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect::<String>();
        let request = build_canonical_request(
            "PUT",
            "/examplebucket/exampleobject",
            "",
            &canonical_headers,
            "content-disposition;content-length",
        );
        assert_eq!(
            hex::encode(Sha256::digest(request.as_bytes())),
            "c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca"
        );
    }

    #[test]
    fn list_all_paginates_and_decodes_keys() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let pages = [
                r#"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next%2Fpage</NextContinuationToken><Contents><Key>root%2Fa.txt</Key><LastModified>2025-01-02T03:04:05Z</LastModified><ETag>&quot;a&quot;</ETag><Size>1</Size></Contents></ListBucketResult>"#,
                r#"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>root%2F%E6%96%87%E4%BB%B6.txt</Key><LastModified>2025-01-02T03:04:05Z</LastModified><ETag>&quot;b&quot;</ETag><Size>2</Size></Contents></ListBucketResult>"#,
            ];
            let mut requests = Vec::new();
            for body in pages {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
            requests
        });
        let client = OssClient::new(&anonymous_config(endpoint), "bucket".into(), None).unwrap();
        let objects = client.list_all("root/").unwrap();
        assert_eq!(
            objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(),
            ["root/a.txt", "root/文件.txt"]
        );
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(
            "GET /bucket/?encoding-type=url&list-type=2&max-keys=1000&prefix=root%2F "
        ));
        assert!(requests[1].contains("continuation-token=next%2Fpage"));
    }

    #[test]
    fn range_read_sends_bounded_http_range() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let body = "cde";
            write!(
                stream,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes 2-4/8\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            request
        });
        let client = OssClient::new(&anonymous_config(endpoint), "bucket".into(), None).unwrap();
        assert_eq!(
            client
                .read_range("root/a b.txt", Some("abc"), 8, 2, 3)
                .unwrap(),
            b"cde"
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /bucket/root/a%20b.txt HTTP/1.1"));
        assert!(request.to_ascii_lowercase().contains("range: bytes=2-4"));
        assert!(request.to_ascii_lowercase().contains("if-match: \"abc\""));
    }

    #[test]
    fn rejects_mismatched_content_range() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: bytes 3-5/8\r\nConnection: close\r\n\r\ncde"
            )
            .unwrap();
        });
        let client = OssClient::new(&anonymous_config(endpoint), "bucket".into(), None).unwrap();
        assert!(client.read_range("key", None, 8, 2, 3).is_err());
        server.join().unwrap();
    }

    #[test]
    fn rejects_repeated_continuation_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                let body = "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken></ListBucketResult>";
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let client = OssClient::new(&anonymous_config(endpoint), "bucket".into(), None).unwrap();
        assert!(client
            .list_all("")
            .unwrap_err()
            .to_string()
            .contains("repeated"));
        server.join().unwrap();
    }

    #[test]
    fn client_does_not_follow_redirects() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", redirect.local_addr().unwrap());
        let destination_url = format!("http://{}/stolen", destination.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = redirect.accept().unwrap();
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {destination_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let client = OssClient::new(&anonymous_config(endpoint), "bucket".into(), None).unwrap();
        assert!(client.list_all("").is_err());
        server.join().unwrap();
        assert!(matches!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        ));
    }
}
