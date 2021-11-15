class UserDoesNotExistException extends Exception {
    public UserDoesNotExistException(String errorMessage) {
        super(errorMessage);
    }
}

class InvalidPasswordException extends Exception {
    public InvalidPasswordException(String errorMessage) {
        super(errorMessage);
    }
}

public class Exceptions {
}
