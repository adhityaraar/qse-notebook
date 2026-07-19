package utils;

public enum Algorithm {
	AES("AES"),
	DH("dh");
	
	private final String _name;
	
	private Algorithm(String name) {
		_name = name;
	}
	
	public String getName() {
		return _name;
	}
}
