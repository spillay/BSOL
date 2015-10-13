#!/usr/bin/perl

use Switch;

my $base = "/opt/opennms/";

my $out = undef;
my $encoding = ":encoding(UTF-8)";

$Input_File     = @ARGV[0];
$TemplateDir	= "configTemplates/";
$ConfigDir	= "configFiles/";

sub read_file {
	my ($filename) = @_;
	open my $in, '<:encoding(UTF-8)', $filename or die "Could not open '$filename' for reading $!";
	local $/ = undef;
	my $all = <$in>;
	close $in;
	return $all;
}
 
sub write_file {
	my ($filename, $content) = @_;
	open my $out, '>:encoding(UTF-8)', $filename or die "Could not open '$filename' for writing $!";;
	print $out $content;
	close $out;
	return;
}

sub process{
	my @list = @_;
	my $templateFile = $TemplateDir . $list[0];
	my $replace = $list[1];
	my $data = $list[2];
	my $outFile = $ConfigDir . $list[0];
	my $filedata = read_file($templateFile);
	$filedata =~ s/$replace/$data/g;
	write_file($outFile, $filedata);
}

sub getSNMPRange{
	my @list = @_;
	$start = $list[0];
	$end = $list[1];
	$snmpversion = $list[2];
	$rocommunity = $list[3];
	$val = "\t<definition version=\"$snmpversion\" read-community=\"$rocommunity\" >\n\t\t<range begin=\"$start\" end=\"$end\"/>\n\t</definition>";
	return $val;
}
sub getSNMPSpecific{
	my @list = @_;
	$start = $list[0];
	$snmpversion = $list[1];
	$rocommunity = $list[2];
	$val = "\t<definition version=\"$snmpversion\" read-community=\"$rocommunity\">\n\t\t<specific>$start</specific>\n\t</definition>";
	return $val;
}
sub getRange{
	my @list = @_;
	$start = $list[0];
	$end = $list[1];
	$val = "<include-range begin=\"$start\" end=\"$end\"/>";
	return $val;
}
sub getSpecific{
	my @list = @_;
	$start = $list[0];
        $val = "<specific>$start</specific>";
	return $val;
}

open INPUT_FILE, $Input_File;
open($out, ">> $encoding", $Output_File);

$data = "";
$snmpdata = "";
while (<INPUT_FILE>) {
	chomp;
	($type,$startip,$endip,$snmpversion,$rocommunity) = split(':');
	print "The type is $type starting at $startip and ending at $endip\n";
	$item = "";
	$snmpitem = "";
	switch($type){
		case "range" { 
			$item = getRange($startip,$endip); 
			$snmpitem = getSNMPRange($startip,$endip,$snmpversion,$rocommunity); 
		}
		case "specific" { 
			$item = getSpecific($startip); 
			$snmpitem = getSNMPSpecific($startip,$snmpversion,$rocommunity); 
		}
	}
	if ( $item ne "" ){
		$data = $data . "\n" . $item;
	}
	if ( $snmpitem ne "" ){
		$snmpdata = $snmpdata . "\n" . $snmpitem;
	}
}

close INPUT_FILE;
print $data;
process("opennms.properties","##BASEDIR##",$base);
process("rrd-configuration.properties","##BLANK##","");
process("collectd-configuration.xml","##INCLUDEIPS##",$data);
process("snmp-config.xml","##DEFINITIONS##",$snmpdata);
process("/snmp-graph.properties.d/spider-graph.properties","##BLANK##","");
process("datacollection-config.xml","##BLANK##","");
process("poll-outages.xml","##BLANK##","");
process("/datacollection/spider.xml","##BLANK##","");
exit(0);

