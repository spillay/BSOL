#!/usr/bin/perl

use Switch;

my $out = undef;
my $encoding = ":encoding(UTF-8)";

$Input_File     = @ARGV[0];
$Output_File = "upload/network.xml";

#------------------------------------
#----- MAIN
#------------------------------------

%forkeys =('none' => 'none');


sub getCategory{
	my @list = @_;
   	print "Given list is @list\n";
	switch($list[0]){
		case "Server" 	{ return "<category name=\"Server\"/>\n<category name=\"$list[1]\"/>\n"; }
		case "Antennae"	{ return "<category name=\"Antennae\"/>\n<category name=\"$list[1]\"/>\n"; }
		case "Router" 	{ return "<category name=\"Router\"/>\n<category name=\"$list[1]\"/>\n"; }
		case "SpiderRadio" 	{ return "<category name=\"SpiderRadio\"/>\n<category name=\"$list[1]\"/>\n"; }
		else { print "No Category for node Type: $list[0] on connection $list[0]"; }
	}
	return "";
}

open INPUT_FILE, $Input_File;
open($out, ">> $encoding", $Output_File);

print $out '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
print $out "\n";
print $out '<model-import foreign-source="wsa-spider" xmlns="http://xmlns.opennms.org/xsd/config/model-import">';
print $out "\n";
 
while (<INPUT_FILE>) {
	chomp;
	($hostname,$ip,$dep,$type,$conn) = split(':');

        sub time_since_epoch { return `date +%s%N` }
        $foreignid = time_since_epoch;
        chomp $foreignid;
	$forkeys{$hostname} = $foreignid;

}
close INPUT_FILE;

@hosts = keys %forkeys;
$sz = @hosts;
for(my $i=0; $i < $sz; $i++){
	print "$hosts[$i]\n";
}
open INPUT_FILE, $Input_File;
while (<INPUT_FILE>) {
	chomp;
	($hostname,$ip,$dep,$type,$conn) = split(':');
	
	$cat = getCategory($type,$conn);
	print "--->$hostname and its category is $cat\n";
        
	sub time_since_epoch { return `date +%s%N` }
        $foreignid = time_since_epoch;
        chomp $foreignid;
	
        print $out '     <node node-label="';
        print $out "$hostname";
        print $out '" foreign-id="';
        print $out "$forkeys{$hostname}";
        print $out '"';
        print "$hostname is dependent on $dep with foreign key $forkeys{$dep}\n";
	if ( $forkeys{$dep} ne "none"){
		print $out " parent-foreign-id=\"$forkeys{$dep}\"";
		print $out ">";
	} else {
		print $out ">";
	}
	print $out "\n";
        print $out '        <interface status="1" snmp-primary="P" ip-addr="';
        print $out "$ip";
        print $out '" descr="">';
        print $out "\n";
        print $out '              <monitored-service service-name="ICMP"/>';
        print $out "\n";
        print $out '              <monitored-service service-name="SNMP"/>';
        print $out "\n";
        print $out '        </interface>';
        print $out "\n";
	print $out $cat;
        print $out '     </node>';
        print $out "\n";

}

print $out '</model-import>';
print $out "\n";
 
close INPUT_FILE;
close $out;
exit(0);
