package qualitychain.inspur.common.logchain;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
/***
*@author yixiao
*/
@Component
public class LogChainUtil {
	private final static String prvKey;
	private final static String requestUrl;
	private static final String SHA_256 = "SHA-256";
	private static final String CHARSET = "UTF-8";
	private static final char strUpper[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private static final String KEY_ALGORITHM = "EC";
    private static final int PARAM_FORMAT_BASE64 = 0;
    private static final int PARAM_FORMAT_HEX = 1;
    static private final int  BASELENGTH   = 128;
    static private final int  LOOKUPLENGTH = 16;
    static final private byte [] hexNumberTable    = new byte[BASELENGTH];
    static final private char [] lookUpHexAlphabet = new char[LOOKUPLENGTH];
    static{
    	 Properties prop = new Properties();
    	 try {
    		 InputStream in = PropertiesFactory.class.getClassLoader().getResourceAsStream("logchain.properties");
    		 prop.load(in);
    		 in.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
    	 prvKey = prop.getProperty("privateKey");
    	 requestUrl = prop.getProperty("requestUrl");
    }
	public static Map<String, Object> logChain(String label,String userId,String logTxt) throws Exception {
		String nodeId = getPid();
		Calendar.getInstance().getTimeInMillis();
		long createdt = Clock.systemDefaultZone().millis();
		String txHash = sha256(userId + label + nodeId + createdt + logTxt).toString();
		PrivateKey privateKey = getPrivateKey(prvKey, 1);
		String signature = sign(txHash, privateKey, PARAM_FORMAT_HEX);
		// 获得Http客户端(可以理解为:你得先有一个浏览器;注意:实际上HttpClient与浏览器是不一样的)
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		// 参数
		Map<String, Object> params = new HashMap<String, Object>();
		Map<String, Object> resultMap = new HashMap<String, Object>();
		// 字符数据最好encoding以下;这样一来，某些特殊字符才能传过去(如:某人的名字就是“&”,不encoding的话,传不过去)
		params.put("user_id", userId);
		params.put("label", label);
		params.put("nodeId", nodeId);
		params.put("createDt", createdt);
		params.put("log_txt", logTxt);
		params.put("txHash", txHash);
		params.put("signature", signature);
		StringEntity sEntity = new StringEntity(JSONObject.toJSONString(params), "utf-8");
		sEntity.setContentType("application/json");
		sEntity.setContentEncoding("utf-8");
		HttpPost httpPost = new HttpPost(requestUrl + "/bas/logchain/put/logs");
		// 设置ContentType(注:如果只是传普通参数的话,ContentType不一定非要用application/json)
		httpPost.setHeader("Content-Type", "application/json;charset=utf-8");
		httpPost.setEntity(sEntity);
		// 响应模型
		CloseableHttpResponse response = null;
		try {
			// 由客户端执行(发送)Post请求
			response = httpClient.execute(httpPost);
			// 从响应模型中获取响应实体
			HttpEntity responseEntity = response.getEntity();
			//System.out.println("响应状态为:" + response.getStatusLine());
			if (responseEntity != null) {
				String resultString = EntityUtils.toString(responseEntity);
				JSONObject jsonObject = JSONObject.parseObject(resultString);
				resultMap = jsonObject;
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				// 释放资源
				if (httpClient != null) {
					httpClient.close();
				}
				if (response != null) {
					response.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return resultMap;
	}
	private static String getPid() {
	    RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
	    String name = runtime.getName();
	    try {
	        return name.substring(0, name.indexOf('@'));
	    } catch (Exception e) {
	        return "-1";
	    }
	}
	/**
	 * SHA_256
	 * @param text
	 * @return
	 */
	private static String sha256(String text){
		return digest(text, CHARSET, SHA_256);
	}
	/**
	 * 摘要计算
	 * @param text
	 * @param charset
	 * @param algorithm
	 * @return
	 */
	private static String digest(String text, String charset, String algorithm){
		try {
			byte[] data = digest(text.getBytes(charset), algorithm);
			return encodeHex(data);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	/**
	 * 摘要计算
	 * @param data
	 * @param algorithm
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] digest(byte[] data, String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm).digest(data);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	/**
	 * 将字节数组转换为16进制字符表示形式
	 * @param data
	 * @return
	 */
	private static String encodeHex(byte[] data) {
		char out[] = new char[data.length << 1];
		for (int i = 0, j = 0; i < data.length; i++) {
			out[j++] = strUpper[(240 & data[i]) >>> 4];
			out[j++] = strUpper[15 & data[i]];
		}
		return String.valueOf(out);
	}
    /**
     * 获取私钥
     * @param privateKey
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(String privateKey, int keyFormat) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        byte[] decodedKey;
        switch (keyFormat) {
            case PARAM_FORMAT_BASE64:
                decodedKey = Base64.decodeBase64(privateKey.getBytes());
                break;
            case PARAM_FORMAT_HEX:
                decodedKey = decode(privateKey);
                break;
            default:
                decodedKey = decode(privateKey);
                break;
        }
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }
    /**
     * ECDSA签名
     * @param data
     * @param privateKey
     * @return
     * @throws Exception
     */
    private static String sign(String data, PrivateKey privateKey, int format) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] sigData = signature.sign();
        String result = "";
        switch (format) {
            case PARAM_FORMAT_BASE64:
                result = new String(Base64.encodeBase64String(sigData));
                break;
            case PARAM_FORMAT_HEX:
                result = encode(sigData);
                break;
            default:
                result = encode(sigData);
                break;
        }
        return result;
    }
    /**
     * Encode a byte array to hex string
     *
     * @param binaryData array of byte to encode
     * @return return encoded string
     */
     private static String encode(byte[] binaryData) {
        if (binaryData == null)
            return null;
        int lengthData   = binaryData.length;
        int lengthEncode = lengthData * 2;
        char[] encodedData = new char[lengthEncode];
        int temp;
        for (int i = 0; i < lengthData; i++) {
            temp = binaryData[i];
            if (temp < 0)
                temp += 256;
            encodedData[i*2] = lookUpHexAlphabet[temp >> 4];
            encodedData[i*2+1] = lookUpHexAlphabet[temp & 0xf];
        }
        return new String(encodedData);
    }
     static {
         for (int i = 0; i < BASELENGTH; i++ ) {
             hexNumberTable[i] = -1;
         }
         for ( int i = '9'; i >= '0'; i--) {
             hexNumberTable[i] = (byte) (i-'0');
         }
         for ( int i = 'F'; i>= 'A'; i--) {
             hexNumberTable[i] = (byte) ( i-'A' + 10 );
         }
         for ( int i = 'f'; i>= 'a'; i--) {
            hexNumberTable[i] = (byte) ( i-'a' + 10 );
         }

         for(int i = 0; i<10; i++ ) {
             lookUpHexAlphabet[i] = (char)('0'+i);
         }
         for(int i = 10; i<=15; i++ ) {
             lookUpHexAlphabet[i] = (char)('A'+i -10);
         }
     }
     /**
      * Decode hex string to a byte array
      *
      * @param encoded encoded string
      * @return return array of byte to encode
      */
     static private byte[] decode(String encoded) {
         if (encoded == null)
             return null;
         int lengthData = encoded.length();
         if (lengthData % 2 != 0)
             return null;

         char[] binaryData = encoded.toCharArray();
         int lengthDecode = lengthData / 2;
         byte[] decodedData = new byte[lengthDecode];
         byte temp1, temp2;
         char tempChar;
         for( int i = 0; i<lengthDecode; i++ ){
             tempChar = binaryData[i*2];
             temp1 = (tempChar < BASELENGTH) ? hexNumberTable[tempChar] : -1;
             if (temp1 == -1)
                 return null;
             tempChar = binaryData[i*2+1];
             temp2 = (tempChar < BASELENGTH) ? hexNumberTable[tempChar] : -1;
             if (temp2 == -1)
                 return null;
             decodedData[i] = (byte)((temp1 << 4) | temp2);
         }
         return decodedData;
     }
}
