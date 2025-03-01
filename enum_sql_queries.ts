export enum node_type {
    CWE = `CREATE TABLE IF NOT EXISTS "global_security_graph"."CWE" (
        "node_uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
        "created_at" timestamp with time zone DEFAULT now() NOT NULL,
        "updated_at" timestamp with time zone DEFAULT now(),
        "archived_at" timestamp with time zone DEFAULT NULL,
        "schema" text ,
        "version" double precision,
        "node_type" text ,
        "data_type" text,
        "provider" text,
        "node_data" jsonb NOT NULL,
        "cweID" text unique)
    ;`,
    CPE = `CREATE TABLE IF NOT EXISTS "global_security_graph"."CPE" (
        "node_uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
        "created_at" timestamp with time zone DEFAULT now() NOT NULL,
        "updated_at" timestamp with time zone DEFAULT now(),
        "archived_at" timestamp with time zone DEFAULT NULL,
        "schema" text ,
        "version" double precision,
        "node_type" text ,
        "data_type" text,
        "provider" text,
        "node_data" jsonb NOT NULL,
        "cpeID" text)
    ;`, 
    CVE = `CREATE TABLE IF NOT EXISTS "global_security_graph"."CVE" (
        "node_uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
        "created_at" timestamp with time zone DEFAULT now() NOT NULL,
        "updated_at" timestamp with time zone DEFAULT now(),
        "archived_at" timestamp with time zone DEFAULT NULL,
        "schema" text ,
        "version" double precision,
        "node_type" text ,
        "data_type" text,
        "provider" text,
        "node_data" jsonb NOT NULL,
        "cveID" text unique)
    ;`,
}