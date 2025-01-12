import 'dart:convert';
import 'dart:math' as math;
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';

Uint8List hashAccessKey(String accessKey, {Uint8List? sessionKey}) {
  var bytes = sha512.convert([
    ...latin1.encode('GateKeeper.accessKey:'),
    ...latin1.encode(accessKey),
  ]).bytes;

  var bytes2 = sha512.convert(bytes).bytes;

  if (sessionKey != null && sessionKey.isNotEmpty) {
    bytes2 = sha512.convert([...bytes2, ...sessionKey]).bytes;
  }

  return Uint8List.fromList(bytes2);
}

Uint8List generateRandomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

Uint8List generateRandomAESKey({int? randomLength}) {
  var keyLng = randomLength != null && randomLength > 0
      ? 32 + math.Random.secure().nextInt(randomLength)
      : 32;
  return generateRandomBytes(keyLng);
}

Uint8List deriveKey(String? password, Uint8List salt,
    {int iterations = 100000, int keyLength = 32}) {
  if (password == null || password.isEmpty) {
    throw ArgumentError(
        "deriveKey> Invalid password: ${password != null ? '"$password"' : 'null'}");
  }

  final keyDerivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
  keyDerivator.init(Pbkdf2Parameters(salt, iterations, keyLength));
  return keyDerivator.process(Uint8List.fromList(utf8.encode(password)));
}

Uint8List deriveKeyFromBytes(List<int>? password, Uint8List salt,
    {int iterations = 100000, int keyLength = 32}) {
  if (password == null || password.isEmpty) {
    throw ArgumentError(
        "deriveKey> Invalid password: ${password != null ? '"$password"' : 'null'}");
  }

  final keyDerivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
  keyDerivator.init(Pbkdf2Parameters(salt, iterations, keyLength));
  return keyDerivator.process(Uint8List.fromList(password));
}

String encryptMessage(Uint8List aesKey, String msg, Uint8List salt) {
  final encrypter = Encrypter(AES(Key(aesKey)));
  var encrypted = encrypter.encrypt(msg, iv: IV(salt)).base64;
  return encrypted;
}

String decryptMessage(Uint8List aesKey, String encrypted, Uint8List salt) {
  var encoded = base64.decode(encrypted.trim());
  final encrypter = Encrypter(AES(Key(aesKey)));
  var decrypted = encrypter.decrypt(Encrypted(encoded), iv: IV(salt));
  return decrypted;
}

final IV _iv = IV.fromBase64('2aYrIaRnlZZCSbxDtXlG/g==');

Uint8List _sessionKeySalt() {
  var now = DateTime.now().toUtc();
  var t = DateTime(now.year, now.month, now.day);
  return deriveKey(
    'session.salt:${t.millisecondsSinceEpoch}',
    _iv.bytes,
    iterations: 10000,
    keyLength: 16,
  );
}

({Uint8List exchangeKey, Uint8List exchangeKeyEncrypted}) generateExchangeKey(
    Uint8List aesKey,
    {bool verbose = false}) {
  var exchangeKey = generateRandomAESKey(randomLength: 32);
  var exchangeKeyEncrypted =
      encryptSessionKey(aesKey, exchangeKey, verbose: verbose);
  return (exchangeKey: exchangeKey, exchangeKeyEncrypted: exchangeKeyEncrypted);
}

Uint8List encryptSessionKey(Uint8List aesKey, Uint8List sessionKey,
    {bool verbose = false}) {
  var sessionKeySalt = _sessionKeySalt();
  if (verbose) {
    print('-- encryptSessionKey> sessionKeySalt: $sessionKeySalt');
  }

  final encrypter = Encrypter(AES(Key(aesKey)));
  return encrypter.encryptBytes(sessionKey, iv: IV(sessionKeySalt)).bytes;
}

Uint8List decryptSessionKey(Uint8List aesKey, Uint8List sessionKeyEncrypted,
    {bool verbose = false}) {
  var sessionKeySalt = _sessionKeySalt();
  if (verbose) {
    print('-- decryptSessionKey> sessionKeySalt: $sessionKeySalt');
  }

  final encrypter = Encrypter(AES(Key(aesKey)));

  var sessionKey = encrypter.decryptBytes(Encrypted(sessionKeyEncrypted),
      iv: IV(sessionKeySalt));

  return Uint8List.fromList(sessionKey);
}
