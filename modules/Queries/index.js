const {Query} = require("@VanillaCX/QueryCX")


const DEKSQuery = new Query({
    database: process.env.QUERYCX_AUTH_DATABASE,
    collection: "DEKS"
});

const SaltsQuery = new Query({
    database: process.env.QUERYCX_AUTH_DATABASE,
    collection: "salts"
});

const UsersQuery = new Query({
    database: process.env.QUERYCX_AUTH_DATABASE,
    collection: "users"
});

const KEKSQuery = new Query({
    database: process.env.QUERYCX_AUTH_DATABASE,
    collection: "KEKS"
});

module.exports = {DEKSQuery, SaltsQuery, UsersQuery, KEKSQuery}