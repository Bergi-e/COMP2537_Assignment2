require('dotenv').config()
const { MongoClient } = require('mongodb')
const host     = process.env.MONGODB_HOST
const user     = process.env.MONGODB_USER
const password = process.env.MONGODB_PASSWORD
const uri      = `mongodb+srv://${user}:${password}@${host}/?retryWrites=true`
const database = new MongoClient(uri, {})
module.exports = { database }
