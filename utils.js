// Function for handling situation where json is already object and there's no need to parse it
export function jsonToObject(json) {
    if (typeof json == 'string') return JSON.parse(json);
    else return json;
}

// Like previous but not
export function objectToJson(obj) {
    if (typeof obj == 'object') return JSON.stringify(obj);
    else return obj
}

// Function for formating user data to readable format
export function formatUser(data) {
    const user = jsonToObject(data);
    return `${user.name || 'Unknown'}[ID: ${user.id || Unknown}]`
}

export const USERNAME_ALLOWED_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-';
export const EMAIL_ALLOWED_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-';
export const PASSWORD_ALLOWED_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-={}[]|;:"<>,.?/~`';

// Function for validating symbols in strings
export function validateString(str, type="username", minLength=3, maxLength=32) {
    let allowedChars = '';
    if (type === "username") allowedChars = USERNAME_ALLOWED_CHARS;
    else if (type === "email") allowedChars = EMAIL_ALLOWED_CHARS;
    else if (type === "password") allowedChars = PASSWORD_ALLOWED_CHARS;
    else throw new Error("Invalid type");

    if (str.length < minLength || str.length > maxLength) return false;
    for (let char of str) {
        if (!allowedChars.includes(char)) return false;
    }
    return true;
}