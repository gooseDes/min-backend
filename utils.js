export function jsonToObject(json) {
    if (typeof json == 'string') return JSON.parse(json);
    else return json;
}