const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const userModel = require("../users/users-model");
const jwt = require('jsonwebtoken');
const sinirli = (req, res, next) => {
  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
    
    try{
      let authHeader = req.headers['authorization'];
      if (!authHeader) {
  
        next({
          status:401,
          message: "Token gereklidir"
        });
      }
      else{
        next({
          status:401,
          message: authHeader
        });
      }
    }
    catch(err){
      next(err);
    }
  
}

const sadece = role_name => (req, res, next) => {
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */
}


const usernameVarmi = async(req, res, next) => {
  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */
  try{
    const {username} = req.body;
    const possible = await userModel.goreBul({username: username});
    if(possible.length===0){
      next({
        status:401,
        message: "Geçersiz kriter"
      })
    }
    else{
      req.user = possible[0];
      next();
    }
  }
  catch(err){
    next(err);
  }
}


const rolAdiGecerlimi = async (req, res, next) => {
  /*
    Bodydeki rol_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
  if(!req.body.role_name || await req.body.role_name.trim() === ""){
    req.body.role_name = "student";
    next();
  }
  else if(await req.body.role_name.trim() === "admin"){
    next({
      status:422,
      message: "Rol adı admin olamaz"
    });
  }
  else if((await req.body.role_name.trim()).length > 32){
    next({
      status:422,
      message: "rol adı 32 karakterden fazla olamaz"
    });
  }
  else{
    req.body.role_name = await req.body.role_name.trim();
    next();
  }
}

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
}
