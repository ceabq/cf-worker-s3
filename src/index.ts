import { Context, Env, Hono } from 'hono'
import * as jose from 'jose'
import { S3Client,GetObjectCommand } from "@aws-sdk/client-s3";
import { getCookie } from 'hono/cookie'
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { Bindings } from 'hono/dist/types/types';

const app = new Hono<{ Bindings: Bindings }>()
app.get('/api2', (c) => c.text('Hello!'))

app.get('*', jwtverifyreq_w_s3 ,s3get)

async function jwtverifyreq_w_s3(c: Context,next: any) {
    let jwttoken = getCookie(c,'jwttoken')
    var pubcert = jose.importX509(c.env.pubcert,'RS256')
    if (jwttoken == undefined) {
        //this stops middleware from excuting further
        return c.newResponse('Token not exist', {status:400})
    }
    else {
        try {
        var { payload, protectedHeader } = await jose.generalVerify({ payload: jwttoken.split('.')[1],
        signatures: [{ signature: jwttoken.split('.')[2],
         protected: jwttoken.split('.')[0] }, ]
       }, await pubcert)}
       catch(e) {
        return new Response(`jwttoken invalid, try login again, ${c.env.loginurl}`)
       }
       let payloaddecodedjson = JSON.parse(new TextDecoder().decode(payload))
        c.set('jwtpayload',payloaddecodedjson)
       if (payloaddecodedjson.exp <= Date.now())
        return new Response("token have expired", {status: 401})
    }
    let s3main = new S3Client({endpoint: c.env.b2endpoint,region: c.env.bucketregion,forcePathStyle:true, credentials: {"accessKeyId": c.env.b2appid,"secretAccessKey": c.env.b2appsecretkey }})
    c.set('s3main', s3main)
    return await next()
}

async function s3get(c:Context) {
    let s3main:S3Client = c.get('s3main')

    //just in case
    if (c.get('jwtpayload') != undefined) {
        let command = new GetObjectCommand({Bucket: c.env.b2bucket, Key: ((new URL(c.req.url)).pathname).replace('/','')})
        let signurl = getSignedUrl(s3main,command,{expiresIn: c.env.s3getexpire})
        return c.redirect(await signurl,302)
    }

}
/*async function token_linktime_distributer(c:Context) {
    c.get("jwtpayload").
    
}
*/
export default app
