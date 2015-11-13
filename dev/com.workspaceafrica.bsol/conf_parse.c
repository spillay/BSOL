//Copyright (C) 2014-2015 Stevens Institute of Tech, Hoboken NJ
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <libxml/parser.h>

#include "vtun.h"

#define BUFFERSIZE 1024 * 1024 * 3
#define READALINE 1024 * 1024 * 1

int conf_parse(struct vtun_host *host)
{
    const char *file = "/usr/local/etc/vtun_conf.xml";
    //const char *file = "/usr/local/etc/link.xml";
    //const char *file = "/home/dsm1000/config/link.xml";

    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;
    xmlNodePtr cur;
    int i = 0;

    vtun_syslog (LOG_ERR,"Attempting to read xml");
    //create a parse
    ctxt = xmlNewParserCtxt();
    //create a file stream
    doc = xmlCtxtReadFile(ctxt, file, "UTF-8", XML_PARSE_DTDATTR|XML_PARSE_NOERROR);
    if (doc == NULL)
    {
        vtun_syslog(LOG_ERR,"Can't parse the content: %s\n", file);
        return 0;
    }
    //get root, it could be access with cur->name
    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        vtun_syslog(LOG_ERR,"Can't get the root element: %s\n", file);
        xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    //get children nodes, it could be access by cur->name
    while (cur != NULL)
    {
        if (!xmlStrcmp(cur->name, (const xmlChar *)"vtun_aggr_conf"))
        {
            xmlChar *key;
            //continue get the children node of this child
            xmlNodePtr l_cur = cur->xmlChildrenNode;
            while (l_cur != NULL && i < VTUN_MAX_INT)
            {
                if (!xmlStrcmp(l_cur->name, (const xmlChar *)"interface"))
                {
                    xmlNodePtr ll_cur = l_cur->xmlChildrenNode;
                    while(ll_cur != NULL)
                    {
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"name"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"name: %s\n", key);
                            host->fs[i].ifa_name = strdup((const char *)key);
                            host->fs[i].ifa_index = if_nametoindex(key);
                            host->ifa_index_hash[if_nametoindex(key)] = i;
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"src_ip"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"src_ip: %s\n", key);
                            host->saddr[i].ip = strdup((const char *)key);
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"src_port"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"src_port: %d\n", atoi(key));
                            host->sport[i] = atoi(key);
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"dst_ip"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"dst_ip: %s\n", key);
                            host->daddr[i].ip = strdup((const char *)key);
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"dst_port"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"dst_port: %d\n", atoi(key));
                            host->dport[i] = atoi(key);
                        }
                        ll_cur = ll_cur->next;
                    }
                    i++;
                }
                l_cur = l_cur->next;
            }
        }
        cur = cur->next;
    }
    host->fscount = i;
    printf ("%d interfaces read from conf\n", host->fscount);

    //free resources
    xmlFreeDoc(doc);
    xmlFreeParserCtxt(ctxt);
    xmlCleanupParser();
    return 0;
}

int parse_sample()
{
    const char *file = "vtun_conf.xml";

    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;
    xmlNodePtr cur;

    //create a parse
    ctxt = xmlNewParserCtxt();
    //create a file stream
    doc = xmlCtxtReadFile(ctxt, file, "UTF-8", XML_PARSE_DTDATTR|XML_PARSE_NOERROR);
    if (doc == NULL)
    {
        vtun_syslog(LOG_ERR,"Can't parse the content: %s\n", file);
        return 0;
    }
    //get root, it could be access with cur->name
    cur = xmlDocGetRootElement(doc);
    if (cur == NULL)
    {
        vtun_syslog(LOG_ERR,"Can't get the root element: %s\n", file);
        xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    //get children nodes, it could be access by cur->name
    while (cur != NULL)
    {
        if (!xmlStrcmp(cur->name, (const xmlChar *)"vtun_aggr_conf"))
        {
            xmlChar *key;
            //continue get the children node of this child
            xmlNodePtr l_cur = cur->xmlChildrenNode;
            while (l_cur != NULL)
            {
                if (!xmlStrcmp(l_cur->name, (const xmlChar *)"interface"))
                {
                    xmlNodePtr ll_cur = l_cur->xmlChildrenNode;
                    while(ll_cur != NULL)
                    {
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"name"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"name: %s\n", key);
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"src_ip"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"src_ip: %s\n", key);
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"src_port"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"src_port: %d\n", atoi(key));
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"dst_ip"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"dst_ip: %s\n", key);
                        }
                        if (!xmlStrcmp(ll_cur->name, (const xmlChar*)"dst_port"))
                        {
                            key = xmlNodeListGetString(doc, ll_cur->xmlChildrenNode, 1);
                            vtun_syslog(LOG_ERR,"dst_port: %d\n", atoi(key));
                        }
                        ll_cur = ll_cur->next;
                    }
                }
                l_cur = l_cur->next;
            }
        }
        else
        {
            vtun_syslog(LOG_ERR,"%s\n", cur->name);
        }
        //get next child
        cur = cur->next;
    }

    //free resources
    xmlFreeDoc(doc);
    xmlFreeParserCtxt(ctxt);
    xmlCleanupParser();
    return 0;
}
