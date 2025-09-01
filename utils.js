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