import 'package:collection/collection.dart';

/// Represents types of tracked events.
enum EventType {
  /// Normal access event.
  access,

  /// Resource not found.
  notFound,

  /// Access denied or invalid.
  badAccess,

  /// Successful login.
  login,
}

/// Represents a single tracked event.
class Event {
  /// Client IP address.
  final String ip;

  /// Type of event.
  final EventType type;

  /// Event timestamp (ms since epoch).
  final int time;

  /// Logged info: may be a user or a bool.
  final Object? logged;

  const Event(this.ip, this.type, this.time, this.logged);

  /// True if the event is from a logged user.
  bool get isLogged {
    final logged = this.logged;
    if (logged == null) {
      return false;
    } else {
      if (logged is bool) return logged;
      return true;
    }
  }

  /// Returns the logged user if available.
  Object? get loggedUser {
    final logged = this.logged;
    if (logged == null || logged is bool) return null;
    return logged;
  }

  /// Returns a new event with modified fields.
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

/// Iterable helpers for [Event].
extension IterableEventExtension on Iterable<Event> {
  /// Filters by IP.
  Iterable<Event> withIP(String ip) => where((e) => e.ip == ip);

  /// Filters by type.
  Iterable<Event> withType(EventType type) => where((e) => e.type == type);

  /// Filters logged events.
  Iterable<Event> logged() => where((e) => e.isLogged);

  /// Returns all logged users (non-null).
  Iterable<Object> loggedUsers() => map((e) => e.loggedUser).nonNulls;

  /// Filters events after [initTime].
  Iterable<Event> after(Object initTime) {
    final initTimeMs = initTime.toTimeMS();
    return where((e) => e.time >= initTimeMs);
  }

  /// Filters events before [endTime].
  Iterable<Event> before(Object endTime) {
    final endTimeMs = endTime.toTimeMS();
    return where((e) => e.time < endTimeMs);
  }

  /// Filters events between [initTime] and [endTime].
  Iterable<Event> between(Object initTime, Object endTime) {
    final initTimeMs = initTime.toTimeMS();
    final endTimeMs = endTime.toTimeMS();
    return where((e) => e.time >= initTimeMs && e.time < endTimeMs);
  }

  /// Filters using optional start/end times.
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

  /// First event time.
  int? init() => firstOrNull?.time;

  /// Last event time.
  int? end() => lastOrNull?.time;

  /// Total time span in ms.
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

  /// Rate per [timeMs] in the selected interval.
  num ratePer(int timeMs, {Object? initTime, Object? endTime}) {
    final l = filterTime(initTime: initTime, endTime: endTime).toList();
    final p = l.period(initTime: initTime, endTime: endTime);
    if (p == null || p == 0) return l.length;
    return l.length / (p / timeMs);
  }
}

/// Possible IP states.
enum IPState { untracked, normal, blocked }

/// Access analysis result.
class AccessState {
  /// Client IP.
  final String ip;

  /// Current IP state.
  final IPState state;

  /// Access rate.
  final num? rate;

  /// Maximum allowed accesses.
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

/// Login analysis result.
class LoginState {
  /// Client IP.
  final String ip;

  /// Count of distinct logged users.
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

/// Detects abuse based on access and login rates.
class GatekeeperAbuse {
  /// Max access per hour for single user.
  final int userMaxAccessPerHour;

  /// Max access multiplier per logged user.
  final int maxAccessUserMultiplier;

  GatekeeperAbuse({
    this.userMaxAccessPerHour =
        200 + (60 * 60 * 10), // 200 + 10/sec (bootstrap + requests/sec)
    this.maxAccessUserMultiplier = 4,
  });

  final QueueList<Event> _accessEvents = QueueList();

  /// Read-only access events.
  List<Event> get accessEvents => UnmodifiableListView(_accessEvents);

  /// Records an access event.
  void notifyAccess(String ip, {bool? logged, Object? time}) => _notifyEvent(
      ip, EventType.access, time?.toTimeMS(), logged, _accessEvents);

  /// Computes IP access state.
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

  /// Computes maximum allowed per hour.
  num computeMaxAccessPerHour(LoginState loginState) {
    final users = loginState.loggedUsers;
    if (users <= 0) return userMaxAccessPerHour;
    return userMaxAccessPerHour * maxAccessUserMultiplier * users;
  }

  /// Computes maximum allowed per [period].
  num computeMaxAccessPer(Duration? period, LoginState loginState) {
    var max = computeMaxAccessPerHour(loginState);
    if (period == null) return max;
    var ratio = (1000 * 60 * 60) / period.inMilliseconds;
    return ratio == 0 ? max : max / ratio;
  }

  final QueueList<Event> _loginEvents = QueueList();

  /// Read-only login events.
  List<Event> get loginEvents => UnmodifiableListView(_loginEvents);

  /// Records a login event.
  void notifyLogin(String ip, Object user, {Object? time}) =>
      _notifyEvent(ip, EventType.login, time?.toTimeMS(), user, _loginEvents);

  /// Computes login state for an IP.
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

/// Time conversion helper.
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

/// Numeric comparison helper.
extension on num? {
  /// True if within [delta].
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
