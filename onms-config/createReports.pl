#!/usr/bin/perl

use strict;
use Switch;

my $base = "/opt/opennms/";

my $out = undef;
my $encoding = ":encoding(UTF-8)";

my $Input_File     = @ARGV[0];
my $TemplateDir	= "configTemplates/";
my $ConfigDir	= "configFiles/";

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

sub getReport {
	my @list = @_;
	my ($reportid,$displayname,$desc) = ($list[0],$list[1],$list[2]);
	my $repData = "<report id=\"$reportid\" display-name=\"$displayname\" online=\"true\" report-service=\"jasperReportService\" description=\"$desc\" />";
	return $repData; 
}

sub getJasperReport {
	my @list = @_;
	my ($reportid,$displayname,$desc,$repfile) = ($list[0],$list[1],$list[2],$list[3]);
	my $repData = "<report id=\"$reportid\" template=\"$repfile\" engine=\"jdbc\" />";
	return $repData; 
}

open INPUT_FILE, $Input_File;
#open($out, ">> $encoding", $Output_File);

my $data1 = "";
my $data2 = "";
while (<INPUT_FILE>) {
	chomp;
	my ($reportid,$displayname,$desc,$repfile) = split(':');
	print "The report id is $reportid and $displayname doing $desc\n";
	$data1 = $data1 . getReport($reportid,$displayname,$desc) . "\n";
	$data2 = $data2 . getJasperReport($reportid,$displayname,$desc,$repfile) . "\n";
}
print $data1 . "\n";
print $data2 . "\n";

process("database-reports.xml","##DATA##",$data1);
process("jasper-reports.xml","##DATA##",$data2);
process("reportd-configuration.xml","##BLANK##","");
process("/report-templates/tabular_list.jrxml","##BLANK##","");
process("/report-templates/blank.jrxml","##BLANK##","");
process("/report-templates/NEW_DATAADAPTER.xml","##BLANK##","");
exit(0);

