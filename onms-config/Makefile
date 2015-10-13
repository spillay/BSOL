ONMSDIR=/usr/share/opennms/
PWD = $(shell pwd)
CONFIGFILES=configFiles/
SNMPGRAPHS=$(CONFIGFILES)snmp-graph.properties.d/
DATACOLLECT=$(CONFIGFILES)datacollection/
REPTEMPLATES=$(CONFIGFILES)report-templates/
REPIMAGES=$(CONFIGFILES)report-templates/assets/images/

all: provision collect reports config

reports:
	if [ ! -d "./$(REPTEMPLATES)" ];then mkdir $(REPTEMPLATES); fi
	./createReports.pl reports.dat
 
provision:
	rm -f upload/network.xml
	./createProvision.pl provisiond.dat
	
collect:
	if [ ! -d "./$(SNMPGRAPHS)" ];then mkdir $(SNMPGRAPHS); fi
	if [ ! -d "./$(DATACOLLECT)" ];then mkdir $(DATACOLLECT); fi
	./createCollect.pl collectiond.dat

up:
	$(ONMSDIR)/bin/send-event.pl -p 'url file://$(PWD)/upload/network.xml' uei.opennms.org/internal/importer/reloadImport 
vacuumd:
	$(ONMSDIR)/bin/send-event.pl   uei.opennms.org/internal/reloadVacuumdConfig

config:
	cp -rv $(CONFIGFILES)/* $(ONMSDIR)/etc/
	cp images/* $(TARGETIMAGES)
up-reports:
	cp -rv $(CONFIGFILES)/jasper-reports.xml $(ONMSDIR)/etc/
	cp -rv $(CONFIGFILES)/database-reports.xml $(ONMSDIR)/etc/
	cp -rv $(CONFIGFILES)/reportd-configuration.xml $(ONMSDIR)/etc/
	cp -rv $(CONFIGFILES)/report-templates/* $(ONMSDIR)/etc/report-templates/
cleandb:
	$(ONMSDIR)/bin/opennms stop
	sh -x deleteall.sh
	$(ONMSDIR)/bin/opennms start &
restart:
	$(ONMSDIR)/bin/opennms restart &
clean:
	rm -rf $(CONFIGFILES)/*
	rm -rf upload/*
