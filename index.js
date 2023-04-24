import {} from 'dotenv/config'
import express from "express";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import { Client } from 'ldapts';
import { verifyToken } from './VerifyToken.js';

//import xxx from './VerifyToken.js';

const app = express();

const config = {
	url: process.env.LDAP_HOST,
	baseDN: process.env.LDAP_BASEDN,
	username: process.env.LDAP_USER,
	password: process.env.LDAP_PASSWORD,
	tlsOptions: {
		rejectUnauthorized: false
	},
	attributes: {
		user: ['dn',
			'userPrincipalName', 'sAMAccountName', 'mail',
			'lockoutTime', 'whenCreated', 'whenChanged',
			'pwdLastSet', 'lastLogon', 'userAccountControl',
			'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
			'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
			'ugPrimaryAffiliation', 'company', 'uid',
			'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
			'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
			'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2'],
		group: ['dn', 'cn', 'description']
	}
}

const client = new Client({
	url: 'ldaps://ug.kth.se',
	timeout: 0,
	connectTimeout: 0,
	tlsOptions: {
	  minVersion: 'TLSv1.2',
	  rejectUnauthorized: false
	},
	strictDN: true,
});

const sizeLimit = parseInt(process.env.SIZE_LIMIT)

const bindDN = process.env.LDAP_USER;
const password = process.env.LDAP_PASSWORD;

try {
	await client.bind(bindDN, password);
} catch (ex) {
	console.log("error code: " + ex.code)
}

const searchDN = 'dc=ug,dc=kth,dc=se';

app.set('apikeyread', process.env.APIKEYREAD);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//CORS

app.use(function (req, res, next) {
	var whitelist = ['kth.se', 'lib.kth.se', 'kth.diva-portal.org']
	/*  
	var origin = req.get('origin');
	whitelist.forEach(function(val, key){
		if (origin.indexOf(val) > -1){
			res.setHeader('Access-Control-Allow-Origin', origin);
		}
	});
	*/
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
	res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType,Content-Type, Accept, Authorization, x-access-token, kth-ug-token");
	next();
});


var apiRoutes = express.Router();

apiRoutes.get('/', function (req, res) {
	res.send('Hello! The API is at https://lib.kth.se/ldap/api/v1');
});


apiRoutes.post("/login", async function (req, res) {
	if(process.env.ENVIRONMENT=='development') {
		console.log(req)
	}
	try {
		await client.bind(req.body.username, req.body.password);
		var token = jwt.sign({ id: req.body.username }, process.env.SECRET, {
			expiresIn: "7d"
		});
		res.status(200).send({ auth: true, token: token });
	} catch (ex) {
		res.status(400).send({ auth: false, error: "wrong credentials" });
	}	
});


apiRoutes.get('/logout', function (req, res) {
	res.status(200).send({ auth: false, token: null });
});

apiRoutes.get("/kthid/:kthid/", verifyToken, async function (req, res, next) {
	try {
		const { searchEntries, searchReferences } = await client.search(
			searchDN,
			{
				filter: `(ugKthid=${req.params.kthid})`,
				sizeLimit: sizeLimit,
				attributes: ['dn',
					'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
					'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2', 'description']
			}
		);
		if (searchEntries.length == 0) {
			res.status(201).send({ 'result': 'kthid ' + req.params.kthid + ' not found' });
			return;
		}
		if (searchEntries.length > 0) {
			res.json({ "ugusers": searchEntries });
		}
	} catch(e) {
		res.status(400).send({ error: e });
	}
});

apiRoutes.get("/account/:account/", verifyToken, async function (req, res, next) {
	try {
		const { searchEntries, searchReferences } = await client.search(
			searchDN,
			{
				filter: `(sAMAccountName=${req.params.account})`,
				sizeLimit: sizeLimit,
				attributes: ['dn',
					'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
					'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2', 'description']
			}
		);
		if (searchEntries.length == 0) {
			res.status(201).send({ 'result': 'Account ' + req.params.account + ' not found' });
			return;
		}
		if (searchEntries.length > 0) {
			res.json({ "ugusers": searchEntries });
		}
	} catch(e) {
		res.status(400).send({ error: e });
	}
});

apiRoutes.get("/userprincipalname/:userprincipalname/", verifyToken, async function (req, res, next) {
	try {
		const { searchEntries, searchReferences } = await client.search(
			searchDN,
			{
				filter: `(userPrincipalName=${req.params.userprincipalname})`,
				sizeLimit: sizeLimit,
				attributes: ['dn',
					'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
					'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2', 'description']
			}
		);
		if (searchEntries.length == 0) {
			res.status(201).send({ 'result': 'Userprincipalname ' + req.params.userprincipalname + ' not found' });
			return;
		}
		if (searchEntries.length > 0) {
			res.json({ "ugusers": searchEntries });
		}
	} catch(e) {
		res.status(400).send({ error: e });
	}
});

apiRoutes.get("/users/:name/", verifyToken, async function (req, res, next) {
	try {
		const { searchEntries, searchReferences } = await client.search(
			searchDN,
			{
				filter: `(cn=${req.params.name})`,
				//sizeLimit: sizeLimit,
				attributes: ['dn',
					'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
					'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2', 'description']
			}
		);
		if (searchEntries.length == 0) {
			res.status(201).send({ 'result': 'Users ' + req.params.name + ' not found' });
			return;
		}
		if (searchEntries.length > 0) {
			res.json({ "ugusers": searchEntries });
		}
	} catch(e) {
		res.status(400).send({ error: e });
	}
});


/**
 * 
 * Hämta apinycklar för divaapan
 * 
 * Vilka ska ha behörighet till dem?
 * 
 * Alla på bibblan ()
 * 
 * pa.anstallda.T.TR	KTH BIBLIOTEKET	
 * pa.anstallda.T.TRAA	VERSAMHETSSTÖD	
 * pa.anstallda.T.TRAB	BIBL.SERVICE & LÄRANDE STÖD	
 * pa.anstallda.T.TRAC	PUBLICERINGENS INFRASTRUKTUR
 * 
 */

apiRoutes.post("/divamonkey", verifyToken, async function (req, res) {
	try {
		const { searchEntries, searchReferences } = await client.search(
			searchDN,
			{
				filter: `(userPrincipalName=${req.userprincipalname})`,
				sizeLimit: sizeLimit,
				attributes: ['dn',
					'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
					'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2', 'description']
			}
		);
		if (searchEntries.length == 0) {
			res.status(201).send({ 'result': 'userPrincipalName ' + req.userprincipalname + ' not found' });
			return;
		}
		if (searchEntries.length > 0) {
			if (searchEntries[0].kthPAGroupMembership) {
				if (searchEntries[0].kthPAGroupMembership.indexOf('pa.anstallda.T.TR') !== -1) {
					res.json(
						{
							"apikeys": {
								"ldap": process.env.LDAPAPIKEY,
								"orcid": process.env.ORCIDAPIKEY,
								"letaanstallda": process.env.LETAANSTALLDAAPIKEY,
								"scopus": process.env.SCOPUSAPIKEY,
								"wos": process.env.WOSAPIKEY,
								"meili": process.env.MEILIPUBLIC
							},
							"token": req.token
						});
				} else {
					res.status(201).send({ "result": 'not authorized' });
				}

			} else {
				res.status(201).send({ "result": 'not authorized' });
			}
		} else {
			res.status(400).send({ 'result': 'General error' });
		}
	} catch(e) {
		res.status(400).send({ error: e });
	}
});

apiRoutes.post("/apikeys", verifyToken, async function (req, res) {
	try {
		const { searchEntries, searchReferences } = await client.search(
			searchDN,
			{
				filter: `(kthid=${req.kthid})`,
				sizeLimit: sizeLimit,
				attributes: ['dn',
					'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
					'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass', 'ugKthid', 'ugVersion', 'ugUsername', 'ugPhone', 'kthPAGroupMembership', 'textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2', 'description']
			}
		);
		if ((!searchEntries)) {
			res.status(201).send({ 'result': 'kthid ' + req.kthid + ' not found' });
			return;
		}
		if (searchEntries.length > 0) {
			if (searchEntries[0].kthPAGroupMembership) {
				if (searchEntries[0].kthPAGroupMembership.indexOf('pa.anstallda.T.TR') !== -1) {
					res.json(
						{
							"apikeys": {
								"ldap": process.env.LDAPAPIKEY,
								"orcid": process.env.ORCIDAPIKEY,
								"letaanstallda": process.env.LETAANSTALLDAAPIKEY,
								"scopus": process.env.SCOPUSAPIKEY,
								"wos": process.env.WOSAPIKEY,
								"meili": process.env.MEILIPUBLIC
							},
							"token": req.token
						});
				} else {
					res.status(201).send({ "result": 'not authorized' });
				}

			} else {
				res.status(201).send({ "result": 'not authorized' });
			}
		} else {
			res.status(400).send({ 'result': 'General error' });
		}
	} catch(e) {
		res.status(400).send({ error: e });
	}
});

app.use(process.env.API_ROUTES_PATH, apiRoutes);

var server = app.listen(process.env.PORT || 3002, function () {
	var port = server.address().port;
	console.log("App now running on port", port);
});
