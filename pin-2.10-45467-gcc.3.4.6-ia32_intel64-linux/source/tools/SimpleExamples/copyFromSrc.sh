Dest=/home/qali/Ins/pin-2.12-54730-gcc.4.4.7-linux/source/tools/SimpleExamples
Src=/home/qali/Src/my-own-pin2-10/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples

if [ $# -lt 1 ]; then
	echo "lack of args"
fi

echo "cp $Src/$1 $Dest"
cp $Src/$1 $Dest

