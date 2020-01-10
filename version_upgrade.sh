#!/bin/bash
## declare an array variable
declare -a arrayT=()
for item in `git config --file .gitmodules --get-regexp submodule  | awk '{ print $2 }'`
do
    arrayT+=($item)
done;

# get length of an array
arraylength=${#arrayT[@]}

# use for loop to read all values and indexes
for (( i=0; i<${arraylength}; i=i+3 ));
do
  directory="${arrayT[$i]}";
  branch="${arrayT[$i+2]}";
  url="${arrayT[$i+1]}";
  cd $directory;
  cd ..;
#  echo  " cd $directory; git checkout $branch; echo changeSomething; git add -A; git commit -m 'version changed'; git push ; cd ..; ";
done
