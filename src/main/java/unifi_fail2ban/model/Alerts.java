//package unifi_fail2ban.model;
//
//import io.vavr.collection.List;
//import lombok.EqualsAndHashCode;
//import lombok.ToString;
//
//@ToString
//@EqualsAndHashCode
//public class Alerts {
//
//    private final List<Alert> matchedEvents;
//
//    Alerts(List<Alert> matchedEvents) {
//        this.matchedEvents = matchedEvents;
//    }
//
//    public List<String> getIpsToBlock() {
//        return matchedEvents.map(Alert::srcIp);
//    }
//}
