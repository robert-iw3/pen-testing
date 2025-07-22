# brew install pandoc
# For latex module
# brew cask install basictex
# For html5 module
# brew cask install wkhtmltopdf
.PHONY : all
.DEFAULT_GOAL := all


MD := $(wildcard *.md)
DOCX := $(MD:.md=.docx)
PDF := $(MD:.md=.pdf)
HTML := $(MD:.md=.html)
targets := $(DOCX) $(PDF) $(HTML) 

base_dir := $(shell basename $(CURDIR))

%.docx: %.md
	pandoc -f  markdown+escaped_line_breaks -t docx\
		-o $@ $? 
		#--reference-doc=template/reference.docx \

%.html: %.md
	pandoc -f  markdown --toc -t html5\
		--self-contained \
		--highlight-style=template/highlight/github-dark.theme \
		-c https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.1.0/github-markdown-dark.css \
		-c template/style.css \
		$? | sed '/<body>/c\<body class="markdown-body">' > $@ 


%.pdf: %.md
	pandoc -f markdown -t latex\
		--pdf-engine=xelatex \
		-V papersize:letter \
		-V geometry:margin=0.75in \
		-H template/disable_float.tex \
		--highlight-style=template/highlight/github-light.theme \
		-o $@ $? 

docx: $(DOCX)

pdf: $(PDF)

html: $(HTML)

all: $(targets) 

clean:
	rm *.html *.docx *.pdf