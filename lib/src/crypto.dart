import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'crypto_utils.dart' as crypto_utils;

export 'crypto_utils.dart' show hashAccessKey;

class AESEncryptor {
  final String accessKey;
  final int iterations;

  AESEncryptor(this.accessKey, {this.iterations = 100000});

  final _iv = base64.decode('HqgZTw7dj1w1lT2t/6qK9Q==');

  Uint8List? _aesKey;

  Uint8List get aesKey => _aesKey ??= deriveKey();

  Uint8List generateRandomBytes(int length) =>
      crypto_utils.generateRandomBytes(length);

  Uint8List generateRandomAESKey({int? randomLength}) =>
      crypto_utils.generateRandomAESKey(randomLength: randomLength);

  Uint8List deriveKey() => crypto_utils.deriveKey(accessKey, _iv,
      iterations: iterations, keyLength: 32);

  String encryptMessage(String msg, Uint8List salt, {Uint8List? aesKey}) {
    aesKey ??= this.aesKey;

    if (msg.isEmpty) {
      msg = '\r\n';
    }

    var encrypted = crypto_utils.encryptMessage(
      aesKey,
      msg,
      salt,
    );

    return encrypted;
  }

  String decryptMessage(String encrypted, Uint8List salt, {Uint8List? aesKey}) {
    aesKey ??= this.aesKey;

    var decrypted = crypto_utils.decryptMessage(
      aesKey,
      encrypted,
      salt,
    );

    if (decrypted == '\r\n') {
      decrypted = '';
    }

    return decrypted;
  }
}

class ChainAESEncryptor {
  final AESEncryptor aesEncryptor;
  final bool server;

  final int seed1;
  final int seed2;

  ChainAESEncryptor(
    this.aesEncryptor, {
    required this.server,
    required this.seed1,
    int? seed2,
  }) : seed2 = seed2 ?? _seed2();

  static int _seed2() {
    var now = DateTime.now().toUtc();
    var t = DateTime.utc(now.year, now.month, now.day);
    var ms = t.millisecondsSinceEpoch;
    return ms;
  }

  final _iv = base64.decode('EII5Psj91EB0drW5C/Xpxg==');

  Uint8List? _salt;
  int _saltIdx = 0;

  Uint8List _nextSalt() {
    return _salt = _generateNextSalt();
  }

  Uint8List _generateNextSalt() {
    var salt = _salt;
    if (salt == null) {
      var iv0 = aesEncryptor._iv;
      var iv1 = _iv;

      var iv = Uint8List.fromList(
        List.generate(iv0.length, (i) => iv0[i] ^ iv1[i]),
      );

      var password = "$seed1:$seed2:$_saltIdx\n"
          "${iv0.join(',')}\n"
          "${iv1.join(',')}";

      var passwordHash = sha256.convert(latin1.encode(password));

      var salt = crypto_utils.deriveKeyFromBytes(
        passwordHash.bytes,
        iv,
        iterations: 1000,
        keyLength: 16,
      );

      return salt;
    } else {
      var iv0 = aesEncryptor._iv;
      var iv1 = _iv;
      ++_saltIdx;

      var iv = Uint8List.fromList(
        List.generate(iv0.length, (i) {
          var b0 = (salt[i] * iv0[i]) % 256;
          var b1 = (salt[i] * iv1[i]) % 256;
          var b = b0 ^ b1;
          return b;
        }),
      );

      var password = "$seed1:$seed2:$_saltIdx\n"
          "${iv0.join(',')}\n"
          "${iv1.join(',')}\n"
          "${iv.join(',')}";

      var passwordHash = sha256.convert(latin1.encode(password));

      var salt2 = crypto_utils.deriveKeyFromBytes(
        passwordHash.bytes,
        iv,
        iterations: 1000 + _saltIdx,
        keyLength: 16,
      );

      return salt2;
    }
  }

  Uint8List? sessionKey;

  String encryptMessage(String msg, {Uint8List? aesKey}) {
    var salt = _nextSalt();
    return aesEncryptor.encryptMessage(msg, salt, aesKey: sessionKey);
  }

  String decryptMessage(String encrypted, {Uint8List? aesKey}) {
    var salt = _nextSalt();
    return aesEncryptor.decryptMessage(encrypted, salt, aesKey: sessionKey);
  }
}
