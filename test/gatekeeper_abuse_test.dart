import 'package:gatekeeper/src/gatekeeper_abuse.dart';
import 'package:test/test.dart';

const ip1 = '192.168.0.1';
const ip2 = '192.168.0.2';
const ip3 = '192.168.0.3';

const period30sec = Duration(seconds: 30);

void main() {
  group('GatekeeperAbuse', () {
    test('basic', () {
      var abuse = GatekeeperAbuse();

      expect(abuse.accessEvents, isEmpty);

      expect(
        abuse.computeAccessState(ip1, period30sec),
        equals(AccessState(ip1, IPState.untracked)),
      );

      ////////////

      abuse.notifyAccess(ip1, time: 1000);

      expect(abuse.accessEvents.length, equals(1));
      expect(abuse.accessEvents.init(), equals(1000));
      expect(abuse.accessEvents.end(), equals(1000));

      expect(
        abuse.computeAccessState(ip1, period30sec),
        equals(AccessState(ip1, IPState.normal, rate: 1)),
      );

      ////////////

      for (var i = 1; i <= 10; ++i) {
        abuse.notifyAccess(ip1, time: 1000 + (i * 1000));
      }

      expect(abuse.accessEvents.length, equals(11));
      expect(abuse.accessEvents.init(), equals(1000));
      expect(abuse.accessEvents.end(), equals(11000));

      expect(
        abuse.computeAccessState(ip1, period30sec, initTime: 1, endTime: 11000),
        equals(AccessState(ip1, IPState.normal, rate: 27.27)),
      );

      ////////////

      for (var i = 1; i <= 10; ++i) {
        abuse.notifyAccess(ip1, time: 11000 + (i * 1000));
      }

      expect(abuse.accessEvents.length, equals(21));
      expect(abuse.accessEvents.init(), equals(1000));
      expect(abuse.accessEvents.end(), equals(21000));

      expect(
        abuse.computeAccessState(ip1, period30sec, initTime: 1, endTime: 11000),
        equals(AccessState(ip1, IPState.normal, rate: 27.27)),
      );

      expect(
        abuse.computeAccessState(ip1, period30sec, initTime: 1, endTime: 21000),
        equals(AccessState(ip1, IPState.normal, rate: 28.57)),
      );

      ////////////

      for (var i = 1; i <= 10; ++i) {
        for (var j = 0; j < 10; ++j) {
          abuse.notifyAccess(ip1, time: 21000 + (i * 1000) + j);
        }
      }

      expect(abuse.accessEvents.length, equals(121));
      expect(abuse.accessEvents.init(), equals(1000));
      expect(abuse.accessEvents.end(), equals(31009));

      expect(
        abuse.computeAccessState(ip1, period30sec, initTime: 1, endTime: 11000),
        equals(AccessState(ip1, IPState.normal, rate: 27.27)),
      );

      expect(
        abuse.computeAccessState(ip1, period30sec, initTime: 1, endTime: 21000),
        equals(AccessState(ip1, IPState.normal, rate: 28.57)),
      );

      expect(
        abuse.computeAccessState(ip1, period30sec, initTime: 1, endTime: 31009),
        equals(AccessState(ip1, IPState.normal, rate: 116.09)),
      );

      expect(
        abuse.computeMaxAccessPer(period30sec, LoginState(ip1, 0)),
        inInclusiveRange(301, 302),
      );
    });
  });
}
