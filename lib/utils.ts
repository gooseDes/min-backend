// Function for handling situation where json is already object and there's no need to parse it
export function jsonToObject(json: any): any {
    if (typeof json == "string") return JSON.parse(json);
    else return json;
}

// Like previous but not
export function objectToJson(obj: any): string {
    if (typeof obj == "object") return JSON.stringify(obj);
    else return obj;
}

// Function for formating user data to readable format
export function formatUser(data: object): string {
    const user = jsonToObject(data);
    return `${user.name || "Unknown"}[ID: ${user.id || "Unknown"}]`;
}

export const USERNAME_ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
export const EMAIL_ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-";
export const PASSWORD_ALLOWED_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-={}[]|;:"<>,.?/~`';

// Function for validating symbols in strings
export function validateString(str: string, type: string = "username", minLength: number = 3, maxLength: number = 32): boolean {
    let allowedChars = "";
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
