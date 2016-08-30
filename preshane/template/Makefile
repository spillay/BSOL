LATEX=pdflatex
PROPNAME=proposal

all: main

spelling:
	aspell -t -c  legal.tex
	aspell -t -c  background-project.tex
	aspell -t -c  scope-project.tex 
	aspell -t -c  exec-project.tex
	aspell -t -c  criteria.tex
	aspell -t -c  structure-project.tex
	aspell -t -c  plan-project.tex
	aspell -t -c  costing-project.tex
	aspell -t -c  acceptance.tex
	aspell -t -c  nda.tex
	aspell -t -c  glossary.tex
clean:
	rm -f $(PROPNAME).aux $(PROPNAME).glo $(PROPNAME).ist $(PROPNAME).log $(PROPNAME).pdf $(PROPNAME).gls $(PROPNAME).glg
main:
	$(LATEX) proposal.tex
	makeindex -s proposal.ist -t proposal.glg -o proposal.gls proposal.glo
	$(LATEX) proposal.tex
	
