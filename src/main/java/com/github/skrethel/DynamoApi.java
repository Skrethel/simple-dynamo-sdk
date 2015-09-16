package com.github.skrethel;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.ini4j.Ini;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;


public class DynamoApi {

	private final String key;
	private final String secret;

	public DynamoApi(String key, String secret) {
		this.key = key;
		this.secret = secret;
	}

	public DynamoApi() throws IOException {
		this("default");
	}

	public DynamoApi(String profileName) throws IOException {
		String homeDir = getHome();

		File credentials = new File(Paths.get(homeDir, ".aws", "credentials").toString());
		if (!(credentials.exists() && credentials.isFile() && credentials.canRead())) {
			throw new IOException("Unable to find ~/.aws/credentials");
		}
		Ini ini = new Ini(credentials);
		key = ini.get(profileName, "aws_access_key_id");
		secret = ini.get(profileName, "aws_secret_access_key");
		if (key == null || secret == null) {
			throw new IOException("Unable to find key and/or secret in profile " + profileName);
		}
	}

	private String getHome() {
		return System.getProperty("user.home");
	}

	private static byte[] HmacSHA256(String data, byte[] key) throws Exception {
		String algorithm = "HmacSHA256";
		Mac mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(key, algorithm));
		return mac.doFinal(data.getBytes("UTF8"));
	}

	private static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
		byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
		byte[] kDate = HmacSHA256(dateStamp, kSecret);
		byte[] kRegion = HmacSHA256(regionName, kDate);
		byte[] kService = HmacSHA256(serviceName, kRegion);
		return HmacSHA256("aws4_request", kService);
	}

	private String getAmzDate(Date date) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(date);
	}

	private String getDateStamp(Date date) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(date);
	}

	private byte[] sha256(String payload) throws Exception {
		return sha256(payload.getBytes("UTF-8"));
	}

	private byte[] sha256(byte[] payload) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(payload);
	}

	private String hex(byte[] payload) {
		return new String(Hex.encodeHex(payload));
	}

	public String listTables(String region) throws Exception {
		return listTables(region, null, null);
	}

	public String listTables(String region, String exclusiveStartTableName, Integer limit) throws Exception {
		String amzTarget = "DynamoDB_20120810.ListTables";
		String payload;
		if (exclusiveStartTableName != null && limit != null) {
			payload = "{\"ExclusiveStartTableName\": " + exclusiveStartTableName + ", \"Limit\": " + limit + "}";
		} else {
			payload = "{}";
		}
		return makeDynamoRequest(region, amzTarget, payload);
	}

	public String getItemWithNumericId(String region, String tableName, boolean consistent, String idFieldName, int id) throws Exception {
		String amzTarget = "DynamoDB_20120810.GetItem";
		String payload = "{ \"TableName\": \"" + tableName + "\", \"ConsistentRead\": " + Boolean.toString(consistent) + ",\"Key\": {\"" + idFieldName + "\": {\"N\" : \"" + id + "\"}}" + "}";
		return makeDynamoRequest(region, amzTarget, payload);
	}

	public String createDynamoTable(String region, String tableDescription) throws Exception {
		String amzTarget = "DynamoDB_20120810.CreateTable";
		return makeDynamoRequest(region, amzTarget, tableDescription);
	}

	@SuppressWarnings("deprecation")
	public String makeDynamoRequest(String region, String amzTarget, String payload) throws Exception {
		// Uncomment to enable http logging
//		System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
//		System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
//		System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");
//		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");
		String method = "POST";
		String service = "dynamodb";
		String contentType = "application/x-amz-json-1.0";
		String host = "dynamodb." + region + ".amazonaws.com";
		String endpoint = "https://" + host;

		String canonicalUri = "/";
		String canonicalQueryString = "";
		Date now = new Date();
		String dateStamp = getDateStamp(now);
		String amzDate = getAmzDate(now);
		String canonicalHeaders = "host:" + host + "\nx-amz-date:" + amzDate + "\nx-amz-target:" + amzTarget + "\n";

		String signedHeaders = "host;x-amz-date;x-amz-target";

		String payloadHash = hex(sha256(payload));

		String canonicalRequest = method + "\n" + canonicalUri + "\n" + canonicalQueryString + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;

		String algorithm = "AWS4-HMAC-SHA256";
		String credentialScope = dateStamp + '/' + region + '/' + service + '/' + "aws4_request";
		String stringToSign = algorithm + '\n' + amzDate + '\n' + credentialScope + '\n' + hex(sha256(canonicalRequest));

		byte[] signingKey = getSignatureKey(secret, dateStamp, region, service);

		String signature = hex(HmacSHA256(stringToSign, signingKey));

		String authorizationHeader = algorithm + " Credential=" + key + '/' + credentialScope + ",SignedHeaders=" + signedHeaders + ", Signature=" + signature;

		HashMap<String, String> headers = new HashMap<>();
		headers.put("Content-Type", contentType);
		headers.put("X-Amz-Date", amzDate);
		headers.put("X-Amz-Target", amzTarget);
		headers.put("Authorization", authorizationHeader);

		HttpClient httpClient = new HttpClient();

		PostMethod httpMethod = new PostMethod(endpoint);
		for (Map.Entry<String, String> entry : headers.entrySet()) {
			httpMethod.addRequestHeader(entry.getKey(), entry.getValue());
		}
		httpMethod.setRequestBody(payload);
		httpClient.executeMethod(httpMethod);
		String body = httpMethod.getResponseBodyAsString();
		httpMethod.releaseConnection();
		return body;
	}

	/*
	 * For testing.
	 */
	public static void main(String[] args) throws Exception {

		DynamoApi dynamoApi = new DynamoApi();
		String tableDescription = "{";
		tableDescription += "\"KeySchema\": [{\"KeyType\": \"HASH\",\"AttributeName\": \"Id\"}],";
		tableDescription += "\"TableName\": \"TestTable\",\"AttributeDefinitions\": [{\"AttributeName\": \"Id\",\"AttributeType\": \"S\"}],";
		tableDescription += "\"ProvisionedThroughput\": {\"WriteCapacityUnits\": 5,\"ReadCapacityUnits\": 5}";
		tableDescription += "}";
		String region = "eu-west-1";
		dynamoApi.createDynamoTable(region, tableDescription);
		dynamoApi.listTables(region);
		dynamoApi.getItemWithNumericId(region, "table_x", true, "id", 1);
	}

}
