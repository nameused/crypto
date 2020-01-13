package org.github.common.exception;

public class EncryptException extends CryptoException {
    private static final String MODULE_NAME="[Encryt]";
    public EncryptException() {
    }

    public EncryptException(String message) {
        super(MODULE_NAME+message);
    }

    public EncryptException(String message, Throwable cause) {
        super(MODULE_NAME+message, cause);
    }

    public EncryptException(Throwable cause) {
        super(cause);
    }

    public EncryptException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(MODULE_NAME+message, cause, enableSuppression, writableStackTrace);
    }
}
