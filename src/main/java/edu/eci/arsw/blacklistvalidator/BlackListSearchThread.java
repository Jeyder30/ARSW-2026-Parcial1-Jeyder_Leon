package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.ArrayList;
import java.util.List;

public class BlackListSearchThread extends Thread {

    private final String ipAddress;
    private final int startServer;
    private final int endServer;
    private final List<Integer> blackListOccurrences = new ArrayList<>();

    public BlackListSearchThread(String ipAddress, int startServer, int endServer) {
        this.ipAddress = ipAddress;
        this.startServer = startServer;
        this.endServer = endServer;
    }

    @Override
    public void run() {
        HostBlacklistsDataSourceFacade dataSource = HostBlacklistsDataSourceFacade.getInstance();

        for (int server = startServer; server < endServer; server++) {
            if (dataSource.isInBlackListServer(server, ipAddress)) {
                blackListOccurrences.add(server);
            }
        }
    }

    public List<Integer> getBlackListOccurrences() {
        return blackListOccurrences;
    }
}
