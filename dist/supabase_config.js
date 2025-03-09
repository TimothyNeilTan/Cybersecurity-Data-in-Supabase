"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const supabaseurl = process.env.SUPABASE_URL;
const supabasekey = process.env.SUPABASE_ANON_KEY;
const supabaseClient = createClient(supabaseurl, supabasekey, { db: { schema: 'global_security_graph' } });
exports.default = supabaseClient;
