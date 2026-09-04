/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT=5;
    
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int N){
        if (N <= 0){
            throw new IllegalArgumentException("El número de hilos debe ser mayor que cero");
        }
        
        LinkedList<Integer> ocurrencias=new LinkedList<>();
        
        HostBlacklistsDataSourceFacade fuente=HostBlacklistsDataSourceFacade.getInstance();
        int totalListas=fuente.getRegisteredServersCount();
        int listasPorHilo=totalListas/N;
        int sobrantes=totalListas%N;
        BlackListSearchThread[] hilos=new BlackListSearchThread[N];
        AtomicInteger ocurrenciasTotales=new AtomicInteger();
        AtomicBoolean terminar=new AtomicBoolean();
        int inicio=0;
        
        for (int i=0;i<N;i++){
            int listasEsteHilo=listasPorHilo+(i<sobrantes ? 1 : 0);
                hilos[i]=new BlackListSearchThread(ipaddress, inicio, inicio+listasEsteHilo,
                    ocurrenciasTotales, terminar);
            hilos[i].start();
            inicio+=listasEsteHilo;
        }
        
        for (BlackListSearchThread hilo : hilos){
            try {
                hilo.join();
                ocurrencias.addAll(hilo.getBlackListOccurrences());
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("La búsqueda fue interrumpida", error);
            }
        }
        
        int totalOcurrencias=ocurrencias.size();
        
        if (totalOcurrencias>=BLACK_LIST_ALARM_COUNT){
            fuente.reportAsNotTrustworthy(ipaddress);
        }
        else{
            fuente.reportAsTrustworthy(ipaddress);
        }                
        
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{totalListas, totalListas});
        
        return ocurrencias;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    
}
