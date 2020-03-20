use ExtUtils::MakeMaker;
use strict;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
     'NAME'      => 'GraphDefang',
     'DISTNAME'  => 'GraphDefang',
     'VERSION'   => '0.91',
     'PREREQ_PM' => { 'File::ReadBackwards'=>'1.00',
                      'GD'=>'2.07',
                      'GD::Graph'=>'1.35',
                      'GD::Text::Align'=>'1.18',
                      'Date::Parse'=>'2.27',
                      'Date::Format'=>'2.22',
                      'MLDBM'=>'2.01',
                      'Storable'=>'2.04'
                    },
     'linkext'   => { LINKTYPE=>'' },
     'PM'	 => { 'graphdefang.pl'=>'graphdefang.pl',
                      'graphdefanglib.pl' => 'graphdefanglib.pl',
                    },
     'dist'      => {'COMPRESS'=>'gzip', 'SUFFIX' => 'gz'}
);

print "\nRun 'make install' to install.\n";
