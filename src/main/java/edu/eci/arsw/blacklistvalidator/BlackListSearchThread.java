package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class BlackListSearchThread extends Thread {

    private final String ipAddress;
    private final int startServer;
    private final int endServer;
    private final AtomicInteger ocurrenciasTotales;
    private final AtomicBoolean terminar;
    private final List<Integer> blackListOccurrences = new ArrayList<>();

    public BlackListSearchThread(String ipAddress, int startServer, int endServer,
            AtomicInteger ocurrenciasTotales, AtomicBoolean terminar) {
        this.ipAddress = ipAddress;
        this.startServer = startServer;
        this.endServer = endServer;
        this.ocurrenciasTotales = ocurrenciasTotales;
        this.terminar = terminar;
    }

    @Override
    public void run() {
        HostBlacklistsDataSourceFacade dataSource = HostBlacklistsDataSourceFacade.getInstance();

        for (int server = startServer; server < endServer && !terminar.get(); server++) {
            if (dataSource.isInBlackListServer(server, ipAddress)) {
                synchronized (ocurrenciasTotales) {
                    if (!terminar.get()) {
                        blackListOccurrences.add(server);
                        if (ocurrenciasTotales.incrementAndGet() >= 5) {
                            terminar.set(true);
                        }
                    }
                }
            }
        }
    }

    public List<Integer> getBlackListOccurrences() {
        return blackListOccurrences;
    }
}
