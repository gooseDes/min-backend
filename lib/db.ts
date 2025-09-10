import { createConnection } from "mysql2/promise";
import type { Connection } from "mysql2/promise";

class Table {
    db: Database;
    name: string;

    constructor(db: Database, name: string) {
        this.db = db;
        this.name = name;
    }

    async addColumn(name: string, data: string = '') {
        await this.db.executeCommand(`ALTER TABLE ${this.name} ADD COLUMN IF NOT EXISTS ${name} ${data}`);
    }

    async addConstraint(name: string, data: string = '') {
        try {
            await this.db.executeCommand(`ALTER TABLE ${this.name} ADD CONSTRAINT ${name} ${data}`);
        } catch {}
    }
}

export class Database {
    connection: Connection | null;
    tables: Table[];

    constructor() {
        this.connection = null;
        this.tables = [];
    }

    async init(db_name: string) {
        this.connection = await createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: 'root',
            password: process.env.DB_PASSWORD || 'root',
            multipleStatements: false
        });
        await this.connection.query(`CREATE DATABASE IF NOT EXISTS ${db_name}`);
        await this.connection.query(`USE ${db_name}`);
    }

    async end() {
        await this.connection?.end()
    }

    async createTable(name: string, has_id: boolean = true): Promise<Table> {
        await this.connection?.query(`CREATE TABLE IF NOT EXISTS ${name} ${has_id ? '(id INT AUTO_INCREMENT PRIMARY KEY)' : '(temp INT)'}`);
        if (!has_id) {
            try {
                await this.connection?.query(`ALTER TABLE ${name} DROP COLUMN temp`);
            } catch {}
        }
        const table = new Table(this, name);
        this.tables.push(table);
        return table;
    }

    async executeCommand(command: string, args: any[] = []) {
        return await this.connection?.query(command, args);
    }
}