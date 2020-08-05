import 'dart:math';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'dart:core';
//Параметры кривой
//NIST Curve P-192:
  //Размер поля
  final p=BigInt.parse("6277101735386680763835789423207666416083908700390324961279");
  //Размерность
  final _n="6277101735386680763835789423176059013767194773182842284081";
  //Длина порядка n
  final nL=_n.length;
  final n=BigInt.parse(_n);
  //Коффактор
  final h=BigInt.one;
  //Параметры кривой
  final a=BigInt.from(-3);
  final b=BigInt.parse("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
  //Базовая точка
  final Gx=BigInt.parse("0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
  final Gy=BigInt.parse("0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811");
  
void main() {
  print("NIST Curve P-192");
  print("ECDSA");
  var msg = "Hello!";
  var hash=hashed(msg);
  print(hash.toString());
  var private_key=rand();
  print("private key: $private_key");
  var public_key = scalar_mult(private_key, Gx,Gy);
  print("public key: $public_key");
  var rez=sign_hash(private_key,hash);
  print(verify_signature(public_key[0],public_key[1],rez[0],rez[1],msg));
}

BigInt hashed(String msg){
  var bytes=utf8.encode("Hello!");
  var digest="0x"+sha256.convert(bytes).toString();
  var dec=BigInt.parse(digest);
  dec=dec>>(dec.bitLength-n.bitLength);
  return dec;
}

//Генератор секретных ключей
BigInt rand(){
  var random = Random.secure();
  var zn = List<String>.generate(nL, (i) => random.nextInt(9).toString());
  var znStr=zn.join();
  var rez=BigInt.parse(znStr);
  if (rez>n-BigInt.one){
    rez=rand();
  }
  return rez;
}

bool is_on_curve(BigInt x, BigInt y){
  var rez=(y.pow(2)- x.pow(3) - a * x - b) % p;
  return  rez.toInt() == 0;
}

List<BigInt> scalar_mult(BigInt k,BigInt x,BigInt y){
  List<BigInt> rez=[BigInt.zero,BigInt.zero],add=[x,y];
  assert (is_on_curve(x,y),"is not on curve");
  if (k < BigInt.zero){
    return scalar_mult(-k, x,y);
  }
    while(k>BigInt.zero){
      if ((k%BigInt.two).toInt()!=0){
        rez = point_add(rez[0],rez[1],add[0],add[1]);
      }
      add = point_add(add[0],add[1],add[0],add[1]);
      k=k>>1;
    }    
return rez;
}

List<BigInt> point_add(BigInt x1,BigInt y1,BigInt x2,BigInt y2){
  BigInt m,x3,y3;
  if (x1==BigInt.zero && y1==BigInt.zero){
    return [x2,y2];
  }
  if (x1==BigInt.zero && y1==BigInt.zero){
    return [x2,y2];
  }
  if (x2==BigInt.zero && y2==BigInt.zero){
    return [x1,y1];
  }     
  if (x1==x2 && y1!=y2){
    return null;
  }
  if (x1==x2){
    var hz1=BigInt.from(3) * x1.pow(2) + a;
    var hz2=BigInt.two * y1;
    m = hz1*hz2.modInverse(p);
  }else{
    m = (y1 - y2)* (x1 - x2).modInverse(p); 
  }
  x3 = m.pow(2) - x1 - x2;
  y3 = y1 + m * (x3 - x1);
  x3=x3 % p;
  y3=-y3 % p;
  return [x3,y3];
}

List<BigInt> sign_hash(BigInt private_key,BigInt hash){
  //Первая подпись
  var r=BigInt.zero;
  //Вторая подпись
  var s=BigInt.zero;
  while(r==BigInt.zero && s==BigInt.zero){
    var k=rand();
    //x точки P
    var x = scalar_mult(k,Gx,Gy);
    r = x[0] % n;
    s = ((hash + r * private_key) * k.modInverse(n)) % n;
    print("r= $r");
    print("s= $s");
    return [r,s];
  }
}

    String verify_signature(BigInt pub1,BigInt pub2,BigInt r,BigInt s,String message){
    var z = hashed(message);
    var w = s.modInverse(n);
    var u1 = (z * w) % n;
    var u2 = (r * w) % n;
    var rU1=scalar_mult(u1,Gx,Gy);
    var rU2=scalar_mult(u2,pub1,pub2);
    var add = point_add(rU1[0],rU1[1],rU2[0],rU2[1]);
    if ((r % n) == (add[0] % n)){
      return "Good signature";
    }else{
      return "invalid signature";
    }         
  }