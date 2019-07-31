package qualitychain.inspur.common.logchain;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class PropertiesFactory {
	

	/**
	 * tagInfo.properties文件
	 */
	private static final PropertiesFactory tagInfoProps = new PropertiesFactory("tagInfo.properties");

	/**
	 * login.properties文件
	 */
	private static final PropertiesFactory loginProps =  new PropertiesFactory("login.properties");

	/**
	 * global.properties文件
	 */
	private static final PropertiesFactory globalProps =  new PropertiesFactory("global.properties");
	
	/**
	 * email.properties文件
	 */
	private static final PropertiesFactory emailProps =  new PropertiesFactory("email.properties");
	
	/**
	 * sms.properties文件
	 */
	private static final PropertiesFactory smsProps =  new PropertiesFactory("sms.properties");

	/**
	 * 资源中心配置
	 */
	private static final PropertiesFactory resProps =  new PropertiesFactory("res.properties");
	
	private final HashMap<String, String> map;
	
	@SuppressWarnings("unchecked")
	private PropertiesFactory(String name) {
		map = new HashMap<String, String>(load(name));
	}
	
	private String getString(String key){
		return map.get(key);
	}
	
	private String getString(String key, String defaultValue){
		String value = getString(key);
		return value == null ? defaultValue : value;
	}
	
	private boolean getBoolean(String key){
		return Boolean.parseBoolean(getString(key));
	}
	
	private int getInteger(String key){
		return Integer.parseInt(getString(key));
	}
	
	private long getLong(String key){
		return Long.parseLong(getString(key));
	}
	
	private double getDouble(String key){
		return Double.parseDouble(getString(key));
	}
	
	private String[] getStringArray(String key){
		return getStringArray(key, ",");
	}
	
	private String[] getStringArray(String key, String separator){
		return getString(key).split(separator);
	}
	
	@SuppressWarnings("rawtypes")
	private Map load(String name){
		InputStreamReader reader = null;
		Properties prop = new Properties();
		try {
			InputStream in = PropertiesFactory.class.getClassLoader().getResourceAsStream(name);
			reader = new InputStreamReader(in, "UTF-8");
			prop.load(reader);
		} catch (RuntimeException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return prop;
	}

}
