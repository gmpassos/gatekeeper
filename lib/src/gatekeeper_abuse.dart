import 'package:collection/collection.dart';

enum EventType {
  access,
  notFound,
  badAccess,
  login,
}

class Event {
  final String ip;
  final EventType type;
  final int time;

  final Object? logged;

  const Event(this.ip, this.type, this.time, this.logged);

  bool get isLogged {
    final logged = this.logged;
    if (logged == null) {
      return false;
    } else {
      if (logged is bool) return logged;
      return true;
    }
  }

  Object? get loggedUser {
    final logged = this.logged;
    if (logged == null || logged is bool) return null;
    return logged;
  }

  Event copyWith({String? ip, EventType? type, int? time, Object? logged}) =>
      Event(ip ?? this.ip, type ?? this.type, time ?? this.time,
          logged ?? this.logged);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Event &&
          runtimeType == other.runtimeType &&
          ip == other.ip &&
          type == other.type &&
          time == other.time &&
          logged == other.logged;

  @override
  int get hashCode => Object.hash(ip, type, time, logged);

  @override
  String toString() => 'Event[$ip]{type: $type, logged: $logged}@$time';
}

extension IterableEventExtension on Iterable<Event> {
  Iterable<Event> withIP(String ip) => where((e) => e.ip == ip);

  Iterable<Event> withType(EventType type) => where((e) => e.type == type);

  Iterable<Event> logged() => where((e) => e.isLogged);

  Iterable<Object> loggedUsers() => map((e) => e.loggedUser).nonNulls;

  Iterable<Event> after(Object initTime) {
    final initTimeMs = initTime.toTimeMS();
    return where((e) => e.time >= initTimeMs);
  }

  Iterable<Event> before(Object endTime) {
    final endTimeMs = endTime.toTimeMS();
    return where((e) => e.time < endTimeMs);
  }

  Iterable<Event> between(Object initTime, Object endTime) {
    final initTimeMs = initTime.toTimeMS();
    final endTimeMs = endTime.toTimeMS();
    return where((e) => e.time >= initTimeMs && e.time < endTimeMs);
  }

  Iterable<Event> filterTime({Object? initTime, Object? endTime}) {
    if (initTime != null) {
      if (endTime != null) {
        return between(initTime, endTime);
      } else {
        return after(initTime);
      }
    } else if (endTime != null) {
      return before(endTime);
    } else {
      return this;
    }
  }

  int? init() => firstOrNull?.time;

  int? end() => lastOrNull?.time;

  int? period({Object? initTime, Object? endTime}) {
    if (initTime != null) {
      if (endTime != null) {
        return endTime.toTimeMS() - initTime.toTimeMS();
      } else {
        var end = this.end();
        if (end != null) {
          return end - initTime.toTimeMS();
        }
      }
    } else if (endTime != null) {
      var init = this.init();
      if (init != null) {
        return endTime.toTimeMS() - init;
      }
    }

    final init = this.init();
    final end = this.end();
    if (init == null || end == null) return null;

    var period = end - init;
    return period;
  }

  num ratePer(int timeMs, {Object? initTime, Object? endTime}) {
    final l = filterTime(initTime: initTime, endTime: endTime).toList();
    final p = l.period(initTime: initTime, endTime: endTime);
    if (p == null || p == 0) return l.length;
    return l.length / (p / timeMs);
  }
}

enum IPState {
  untracked,
  normal,
  blocked;
}

class AccessState {
  final String ip;
  final IPState state;
  final num? rate;
  final num? maxAccess;

  const AccessState(this.ip, this.state, {this.rate, this.maxAccess});

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AccessState &&
          runtimeType == other.runtimeType &&
          ip == other.ip &&
          state == other.state &&
          rate.eq(other.rate, 0.01) &&
          maxAccess.eq(other.maxAccess, 0.99);

  @override
  int get hashCode => Object.hash(ip, state, rate, maxAccess);

  @override
  String toString() =>
      'AccessState[$ip]{state: $state, rate: $rate, maxAccess: $maxAccess}';
}

class LoginState {
  final String ip;
  final int loggedUsers;

  const LoginState(this.ip, this.loggedUsers);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is LoginState &&
          runtimeType == other.runtimeType &&
          ip == other.ip &&
          loggedUsers == other.loggedUsers;

  @override
  int get hashCode => Object.hash(ip, loggedUsers);

  @override
  String toString() => 'LoginState[$ip]{loggedUsers: $loggedUsers}';
}

class GatekeeperAbuse {
  final int userMaxAccessPerHour;
  final int maxAccessUserMultiplier;

  GatekeeperAbuse({
    this.userMaxAccessPerHour =
        200 + (60 * 60 * 10), // 200 + 10/sec (bootstrap + requests/sec)
    this.maxAccessUserMultiplier = 4,
  });

  final QueueList<Event> _accessEvents = QueueList();

  List<Event> get accessEvents => UnmodifiableListView(_accessEvents);

  void notifyAccess(String ip, {bool? logged, Object? time}) => _notifyEvent(
      ip, EventType.access, time?.toTimeMS(), logged, _accessEvents);

  AccessState computeAccessState(String ip, Duration period,
      {Object? initTime, Object? endTime}) {
    final ipEvents = _accessEvents
        .withIP(ip)
        .filterTime(initTime: initTime, endTime: endTime)
        .toList();

    if (ipEvents.isEmpty) return AccessState(ip, IPState.untracked);

    final rate = ipEvents.ratePer(period.inMilliseconds,
        initTime: initTime, endTime: endTime);
    if (rate <= 0) return AccessState(ip, IPState.normal, rate: 0);

    final loginState =
        computeLoginState(ip, initTime: initTime, endTime: endTime);

    final maxAccess = computeMaxAccessPer(period, loginState);

    if (rate > maxAccess) {
      return AccessState(ip, IPState.blocked, rate: rate, maxAccess: maxAccess);
    }

    return AccessState(ip, IPState.normal, rate: rate, maxAccess: maxAccess);
  }

  num computeMaxAccessPerHour(LoginState loginState) {
    final users = loginState.loggedUsers;
    if (users <= 0) return userMaxAccessPerHour;
    return userMaxAccessPerHour * maxAccessUserMultiplier * users;
  }

  num computeMaxAccessPer(Duration? period, LoginState loginState) {
    var max = computeMaxAccessPerHour(loginState);
    if (period == null) return max;
    var ratio = (1000 * 60 * 60) / period.inMilliseconds;
    return ratio == 0 ? max : max / ratio;
  }

  final QueueList<Event> _loginEvents = QueueList();

  List<Event> get loginEvents => UnmodifiableListView(_loginEvents);

  void notifyLogin(String ip, Object user, {Object? time}) =>
      _notifyEvent(ip, EventType.login, time?.toTimeMS(), user, _loginEvents);

  LoginState computeLoginState(String ip, {Object? initTime, Object? endTime}) {
    final ipEvents = _loginEvents
        .withIP(ip)
        .filterTime(initTime: initTime, endTime: endTime)
        .toList();
    if (ipEvents.isEmpty) return LoginState(ip, 0);
    final users = ipEvents.loggedUsers().toSet();
    return LoginState(ip, users.length);
  }

  void _notifyEvent(String ip, EventType type, int? time, Object? logged,
      QueueList<Event> events) {
    events.add(
        Event(ip, type, time ?? DateTime.now().millisecondsSinceEpoch, logged));
  }
}

extension on Object {
  int toTimeMS() {
    final self = this;
    if (self is int) {
      return self;
    } else if (self is DateTime) {
      return self.millisecondsSinceEpoch;
    } else {
      throw StateError("Not an `int` or `DateTime`: $this");
    }
  }
}

extension on num? {
  bool eq(num? other, num delta) {
    final self = this;

    if (self == null) {
      return other == null;
    } else if (other == null) {
      return false;
    }

    final d = self - other;

    if (d == 0) {
      return true;
    } else if (d < 0) {
      return -delta < d;
    } else {
      return d < delta;
    }
  }
}
