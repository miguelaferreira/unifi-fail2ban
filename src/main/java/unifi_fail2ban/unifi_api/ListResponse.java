package unifi_fail2ban.unifi_api;

import java.util.List;

public interface ListResponse<T> {

    List<T> data();

    int getAvailable();
}
