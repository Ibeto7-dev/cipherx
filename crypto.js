/* CipherX v1: PBKDF2-SHA256 / AES-256-GCM. Random salt and IV per operation. */
const CipherX = (()=>{
 const enc=new TextEncoder(), dec=new TextDecoder('utf-8',{fatal:true});
 const b64=a=>{let s='';for(let i=0;i<a.length;i+=8192)s+=String.fromCharCode(...a.subarray(i,i+8192));return btoa(s)};
 const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 async function key(password,salt){const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
 async function encrypt(data,password){const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));const k=await key(password,salt);const body=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},k,data));return 'CX1.'+b64(salt)+'.'+b64(iv)+'.'+b64(body)}
 async function decrypt(value,password){const p=value.trim().split('.');if(p.length!==4||p[0]!=='CX1')throw Error('صيغة التشفير غير صالحة. استخدم نتيجة صادرة من هذه الأداة.');const salt=unb64(p[1]),iv=unb64(p[2]),body=unb64(p[3]);if(salt.length!==16||iv.length!==12||body.length<16)throw Error('بيانات مشفّرة غير صالحة.');try{return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv},await key(password,salt),body))}catch{throw Error('تعذّر فك التشفير: كلمة المرور غير صحيحة أو البيانات تغيّرت.')}}
 function password(length,groups){const sets=['abcdefghijklmnopqrstuvwxyz',...groups];const all=sets.join('');function pick(s){const limit=256-256%s.length;let x;do{x=crypto.getRandomValues(new Uint8Array(1))[0]}while(x>=limit);return s[x%s.length]}const out=sets.map(pick);while(out.length<length)out.push(pick(all));for(let i=out.length-1;i>0;i--){let j;const max=256-256%(i+1);do{j=crypto.getRandomValues(new Uint8Array(1))[0]}while(j>=max);j%=i+1;[out[i],out[j]]=[out[j],out[i]]}return out.join('')}
 return {encrypt,decrypt,password,enc,dec};
})();
if(typeof module!=='undefined')module.exports=CipherX;
