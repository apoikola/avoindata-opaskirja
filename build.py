#!/usr/bin/env python

import fnmatch
import os
import pprint
import subprocess
from subprocess import CalledProcessError

CURDIR = os.path.dirname(os.path.abspath(__file__))
print(CURDIR)
BUILDDIR = os.path.join(CURDIR, 'pandoc')
TARGET_HTML = os.path.join(BUILDDIR, 'julkinen_data.html')
CSS_TEMPLATE = os.path.join(BUILDDIR, 'templates', 'default.css')
HTML_TEMPLATE = os.path.join(BUILDDIR, 'templates', 'default.html')

matches = []
for root, dirnames, filenames in os.walk(CURDIR):
  for filename in fnmatch.filter(filenames, '*.markdown'):
      matches.append(os.path.join(root, filename))

matches.sort()

args = ['pandoc']
args.extend(matches)
args.extend(['-o', TARGET_HTML, '--template', HTML_TEMPLATE, '--css', CSS_TEMPLATE, '-t', 'html5'])

#pprint.pprint(args)
try:
	print('Converting to HTML...')
	subprocess.check_call(args)
	print('Done')
except CalledProcessError, e:
	print(e)
