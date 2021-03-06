#!/bin/bash

## Defaults
PYTHON_PREFIX="/usr"
PYTHON_VERSION="python2.7"
JAVA_FLAGS=""
EXECUTABLE_NAME="exaudfclient"
LIBEXAUDF_NAME="libexaudflib"

optarr=$(getopt -o 'h' --long 'libexaudf-name:,executable-name:,help,src-dir:,build-dir:,output-dir:,enable-r,enable-java,enable-python,python-prefix:,python-version:,python-syspath:,enable-streaming,custom-protobuf-prefix:,release-sources,java-flags:' -- "$@")

eval set -- "$optarr"

while true; do
    case "$1" in
        --libexaudf-name) LIBEXAUDF_NAME="$2"; shift 2;;
        --executable-name) EXECUTABLE_NAME="$2"; shift 2;;
        --src-dir) SRCDIR="$2"; shift 2;;
        --build-dir) BUILDDIR="$2"; shift 2;;
        --output-dir) OUTPUTDIR="$2"; shift 2;;
        --enable-python) ENABLE_PYTHON_IMPL="yes"; shift 1;;
        --python-prefix) PYTHON_PREFIX="$2"; shift 2;;
        --python-version) PYTHON_VERSION="$2"; shift 2;;
        --python-syspath) PYTHON_SYSPATH="$2"; shift 2;;
        --enable-r) ENABLE_R_IMPL="yes"; shift 1;;        
        --enable-java) ENABLE_JAVA_IMPL="yes"; shift 1;;
	--java-flags) JAVA_FLAGS="$2"; shift 2;;
        --enable-streaming) ENABLE_STREAMING_IMPL="yes"; shift 1;;
        --custom-protobuf-prefix) CUSTOM_PROTOBUF_PREFIX="$2"; shift 2;;
	--release-sources) RELEASE_SOURCES="yes"; shift 1;;
        -h|--help) echo "Usage: $0 --src-dir=<dir> --build-dir=<dir> --output-dir=<>"
		   echo "Options:"
		   echo "  [--enable-python]   Enable support for the Python language in the script language client"
		   echo "  [--enable-r]        Enable support for the R language in the script language client"
		   echo "  [--enable-java]     Enable support for the Java language in the script language client"
		   echo "  [-h|--help]         Print this help."; exit 0;;
        --) shift; break;;
        *) echo "Internal error while parsing arguments. ($1)"; exit 1;;
    esac
done

#LD_LIBRARY_PATH=${PYTHON_PREFIX}/lib:${#LD_LIBRARY_PATH}

die() { echo "ERROR:" "$@" >&2; exit 1; }

[ X"$SRCDIR" = X"" ] && die "Missing mandatory argument --src-dir"
[ X"$BUILDDIR" = X"" ] && die "Missing mandatory argument --build-dir"
[ X"$OUTPUTDIR" = X"" ] && die "Missing mandatory argument --output-dir"
[ -d "$SRCDIR" ] || die "Directory specified via --src-dir does not exist: $SRCDIR"
[ -d "$BUILDDIR" ] || die "Directory specified via --build-dir does not exist: $BUILDDIR"
[ -d "$OUTPUTDIR" ] || die "Directory specified via --output-dir does not exist: $OUTPUTDIR"

cd $SRCDIR || die "Cannot change the current directory to $SRCDIR"

mkdir -p  "$BUILDDIR"  "$BUILDDIR/java_src/com/exasol" || die "Failed to create directories in $BUILDDIR"

export PATH=$PYTHON_PREFIX/bin:$PATH

# Copy source code to the build dir
echo "Copying common source files to the build dir"
for SRC in \
        zmqcontainer.proto exascript.i filter_swig_code.py build_integrated.py exaudfclient.cc exaudflib* \
        script_data_transfer_objects* LICENSE-exasol-script-api.txt scriptoptionlines.h scriptoptionlines.cc \
        python_ext_dataframe.cc
do
    cp "$SRC" "$BUILDDIR/" || die "Failed to copy file $SRC to build dir: $BUILDDIR."
done


if [ "$ENABLE_STREAMING_IMPL" = "yes" ]; then
    # Python
    echo "Copying Streaming related files to the build dir"
    for SRC in \
        streamingcontainer.cc
    do
        cp "$SRC" "$BUILDDIR/" || die "Failed to copy file $SRC to build dir: $BUILDDIR."
    done
fi


if [ "$ENABLE_PYTHON_IMPL" = "yes" ] ; then
    # Python
    echo "Copying Python related files to the build dir"
    for SRC in \
        pythoncontainer.cc exascript_python_preset.py exascript_python_wrap.py
    do
	cp "$SRC" "$BUILDDIR/" || die "Failed to copy file $SRC to build dir: $BUILDDIR."
    done
fi

if [ "$ENABLE_R_IMPL" = "yes" ]; then
    # R
    echo "Copying R related files to the build dir"
    for SRC in \
        rcontainer.cc exascript_r_preset.R exascript_r_wrap.R
    do
	cp "$SRC" "$BUILDDIR/" || die "Failed to copy file $SRC to build dir: $BUILDDIR."
    done
fi

if [ "$ENABLE_JAVA_IMPL" = "yes" ]; then
    # Java
    echo "Copying Java related files to the build dir"
    for SRC in \
        javacontainer.cc exascript_java_jni_decl.h
    do
	cp "$SRC" "$BUILDDIR/" || die "Failed to copy file $SRC to build dir: $BUILDDIR."
    done

    # Copy java code to chroot environment
    for SRC in ExaCompilationException.java       ExaExportSpecification.java      ExaIteratorImpl.java \
						  ExaCompiler.java                   ExaExportSpecificationImpl.java  ExaMetadata.java \
						  ExaConnectionAccessException.java  ExaImportSpecification.java      ExaMetadataImpl.java \
						  ExaConnectionInformation.java      ExaImportSpecificationImpl.java  ExaUndefinedSingleCallException.java \
						  ExaConnectionInformationImpl.java  ExaIterationException.java       ExaWrapper.java \
						  ExaDataTypeException.java          ExaIterator.java
    do
	cp "javacontainer/$SRC" "$BUILDDIR/java_src/com/exasol/" || die "Failed to copy file $SRC to $BUILDDIR/java_src/com/exasol/."
    done
fi

cd $BUILDDIR || die "No $BUILDDIR directory found"

# create source code from proto files
if [ "X$CUSTOM_PROTOBUF_PREFIX" = "X" ]; then
    protoc -I. zmqcontainer.proto --cpp_out=. || die "Failed to create C++ proto files."
else
    $CUSTOM_PROTOBUF_PREFIX/bin/protoc -I. zmqcontainer.proto --cpp_out=. || die "Failed to create C++ proto files."
fi
#/usr/local/protoc zmqcontainer.proto --python_out=. || die "Failed to create Python proto files."


export CXXFLAGS="-I. -I/usr/include -I/usr/local -Wall -Werror -fPIC -pthread -DNDEBUG -std=c++14 -O3 -DLIBEXAUDF_NAME=\"$LIBEXAUDF_NAME\" "
#export CXXFLAGS="-I. -I/usr/include -I/usr/local -Wall -Werror -fPIC -pthread -DNDEBUG -std=c++14 -O0 -g"
export CXXFLAGS_UNOPT="-I. -Wall -Werror -fPIC -pthread -DNDEBUG -std=c++14"
LIBS="-lpthread -lcrypto -ldl -lzmq"
LDFLAGS=""


if [ "$ENABLE_STREAMING_IMPL" = "yes" ]; then

    CXXFLAGS="-DENABLE_STREAMING_VM $CXXFLAGS"

    echo "Compiling Streaming specific code"
    g++ -o streamingcontainer.o -c streamingcontainer.cc $CXXFLAGS || die "Failed to compile streamingcontainer.o"

    CONTAINER_CLIENT_OBJECT_FILES="streamingcontainer.o $CONTAINER_CLIENT_OBJECT_FILES"
fi




if [ "$ENABLE_PYTHON_IMPL" = "yes" ]; then
    PYTHON_CONFIG="${PYTHON_VERSION}-config"
    ACTUAL_PYTHON_VERSION=`${PYTHON_PREFIX}/bin/${PYTHON_VERSION} -c 'import sys; print(".".join(map(str, sys.version_info[:3])))'`
   
    hash "${PYTHON_VERSION}-config" && PYTHON_CONFIG="${PYTHON_VERSION}-config"

    echo "Generating Python SWIG code using python-config: $PYTHON_CONFIG"
    # create python wrapper from swig files
    swig $($PYTHON_CONFIG --includes) -O -DEXTERNAL_PROCESS -Wall -c++ -python -py3 -addextern -module exascript_python -o exascript_python_tmp.cc exascript.i || die "SWIG compilation failed."
    swig $($PYTHON_CONFIG --includes) -DEXTERNAL_PROCESS -c++ -python -py3 -external-runtime exascript_python_tmp.h || die "SWIG compilation failed."

    mv exascript_python_preset.py exascript_python_preset.py_orig
    echo "import sys, os" > exascript_python_preset.py
    
    echo "sys.path.extend($($PYTHON_PREFIX/bin/${PYTHON_VERSION} -c 'import sys; import site; print(sys.path)'))" >> exascript_python_preset.py

    if [ ! "X$PYTHON_SYSPATH" = "X" ]; then
        echo "sys.path.extend($PYTHON_SYSPATH)" >> exascript_python_preset.py
    fi
    
    cat exascript_python_preset.py_orig >> exascript_python_preset.py
    
    python ./build_integrated.py exascript_python_int.h exascript_python.py exascript_python_wrap.py exascript_python_preset.py || die "Failed build_integrated"

       
    if [[ $ACTUAL_PYTHON_VERSION == 2* ]] ; then
        python ./filter_swig_code.py exascript_python.h exascript_python_tmp.h || die "Failed: filter_swig_code.py exascript_python.h exascript_python_tmp.h"
        python ./filter_swig_code.py exascript_python.cc exascript_python_tmp.cc || die "exascript_python.cc exascript_python_tmp.cc"
    fi

    cp exascript_python_tmp.h exascript_python.h || die "Failed: filter_swig_code.py exascript_python.h exascript_python_tmp.h"
    cp exascript_python_tmp.cc exascript_python.cc || die "exascript_python.cc exascript_python_tmp.cc"

    CXXFLAGS="-DENABLE_PYTHON_VM $($PYTHON_CONFIG --includes) $CXXFLAGS"
    if [[ $ACTUAL_PYTHON_VERSION == 3* ]] ; then
        CXXFLAGS="-DENABLE_PYTHON3 $CXXFLAGS"
    fi
    LIBS="$($PYTHON_CONFIG --libs) $LIBS"
    LDFLAGS="-L$($PYTHON_CONFIG --prefix)/lib -Wl,-rpath,$($PYTHON_CONFIG --prefix)/lib $LDFLAGS" 

    echo "Compiling Python specific code with these CXXFLAGS:$CXXFLAGS"
    g++ -o exascript_python.o -c exascript_python.cc $CXXFLAGS -Wno-unused-but-set-variable || die "Failed to compile exascript_python.o"
    g++ -o pythoncontainer.o -c pythoncontainer.cc $CXXFLAGS || die "Failed to compile pythoncontainer.o"
    if [[ $ACTUAL_PYTHON_VERSION == 3* ]] ; then
        g++ -shared $CXXFLAGS -I/usr/local/lib/$PYTHON_VERSION/dist-packages/numpy/core/include $($PYTHON_CONFIG --libs) -opyextdataframe.so python_ext_dataframe.cc || die "Failed to compile pyextdataframe.so"
    fi

    CONTAINER_CLIENT_OBJECT_FILES="exascript_python.o pythoncontainer.o $CONTAINER_CLIENT_OBJECT_FILES"
fi


if [ "$ENABLE_R_IMPL" = "yes" ]; then
    # create R wrapper from swig files
    swig -O -DEXTERNAL_PROCESS -Wall -c++ -r -addextern -module exascript_r -o exascript_r_tmp.cc exascript.i >/dev/null 2>&1 || die "SWIG compilation failed."
    swig -DEXTERNAL_PROCESS -c++ -r -external-runtime exascript_r_tmp.h || die "SWIG compilation failed."


    python ./build_integrated.py exascript_r_int.h exascript_r.R exascript_r_wrap.R exascript_r_preset.R 
    python ./filter_swig_code.py exascript_r.h exascript_r_tmp.h
    python ./filter_swig_code.py exascript_r.cc exascript_r_tmp.cc

    LIBS="-lR $LIBS"
    CXXFLAGS="-DENABLE_R_VM -I/usr/share/R/include $CXXFLAGS"

    g++ -o exascript_r.o -c exascript_r.cc $CXXFLAGS || die "Failed to compile exascript_r.o"
    g++ -o rcontainer.o -c rcontainer.cc $CXXFLAGS || die "Failed to compile rcontainer.o"

    CONTAINER_CLIENT_OBJECT_FILES="exascript_r.o rcontainer.o $CONTAINER_CLIENT_OBJECT_FILES"
fi

if [ "$ENABLE_JAVA_IMPL" = "yes" ]; then
    # create java wrapper from swig files
    mkdir -p java_src/com/exasol/swig || die "Failed to create directory java_src/com/exasol/swig"
    swig -O -DEXTERNAL_PROCESS -Wall -c++ -java -addextern -module exascript_java -package com.exasol.swig -outdir java_src/com/exasol/swig -o exascript_java_tmp.cc exascript.i || die "SWIG compilation failed."
    swig -DEXTERNAL_PROCESS -c++ -java -external-runtime exascript_java_tmp.h || die "SWIG compilation failed."

    python ./build_integrated.py exascript_java_int.h java_src/com/exasol/swig/exascript_java.java java_src/com/exasol/swig/exascript_javaJNI.java java_src/com/exasol/swig/SWIGVM_datatype_e.java java_src/com/exasol/swig/SWIGVM_itertype_e.java java_src/com/exasol/swig/Metadata.java java_src/com/exasol/swig/TableIterator.java java_src/com/exasol/swig/ResultHandler.java java_src/com/exasol/swig/ConnectionInformationWrapper.java java_src/com/exasol/swig/ImportSpecificationWrapper.java java_src/com/exasol/swig/SWIGTYPE_p_ExecutionGraph__ImportSpecification.java java_src/com/exasol/swig/ExportSpecificationWrapper.java java_src/com/exasol/swig/SWIGTYPE_p_ExecutionGraph__ExportSpecification.java					 

    python ./filter_swig_code.py exascript_java.cc exascript_java_tmp.cc
    python ./filter_swig_code.py exascript_java.h exascript_java_tmp.h

    LIBS="-ljvm $LIBS"
    #LDFLAGS="-L/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64 -L/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server -Wl,-rpath,/usr/lib/jvm/java-8-openjdk-amd64/lib/amd64 -Wl,-rpath,/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server $LDFLAGS"
    #CXXFLAGS="-DENABLE_JAVA_VM -I/usr/lib/jvm/java-8-openjdk-amd64/include -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux $CXXFLAGS"
    #CXXFLAGS_UNOPT="-DENABLE_JAVA_VM -I/usr/lib/jvm/java-8-openjdk-amd64/include -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux $CXXFLAGS_UNOPT"
    LDFLAGS="$JAVA_FLAGS $LDFLAGS"
    CXXFLAGS="-DENABLE_JAVA_VM $JAVA_FLAGS $CXXFLAGS"
    CXXFLAGS_UNOPT="-DENABLE_JAVA_VM $JAVA_FLAGS $CXXFLAGS_UNOPT"

    LDFLAGS="-L/usr/lib/jvm/java-9-openjdk-amd64/lib -L/usr/lib/jvm/java-9-openjdk-amd64/lib/amd64 -L/usr/lib/jvm/java-9-openjdk-amd64/lib/amd64/server -Wl,-rpath,/usr/lib/jvm/java-9-openjdk-amd64/lib -Wl,-rpath,/usr/lib/jvm/java-9-openjdk-amd64/lib/amd64 -Wl,-rpath,/usr/lib/jvm/java-9-openjdk-amd64/lib/amd64/server $LDFLAGS"
    
    CXXFLAGS="-DENABLE_JAVA_VM -I/usr/lib/jvm/java-9-openjdk-amd64/include -I/usr/lib/jvm/java-9-openjdk-amd64/include/linux $CXXFLAGS"
    CXXFLAGS_UNOPT="-DENABLE_JAVA_VM -I/usr/lib/jvm/java-9-openjdk-amd64/include -I/usr/lib/jvm/java-9-openjdk-amd64/include/linux $CXXFLAGS_UNOPT"



    g++ -o exascript_java.o -c exascript_java.cc $CXXFLAGS_UNOPT  || die "Failed to compile exascript_java.o"
    g++ -o javacontainer.o -c javacontainer.cc $CXXFLAGS || die "Failed to compile javacontainer.o"
    
    CONTAINER_CLIENT_OBJECT_FILES="exascript_java.o javacontainer.o $CONTAINER_CLIENT_OBJECT_FILES"

# compile java code and create jar file for java container
mkdir -p udf || die "Failed to create udf directory"
#javac -bootclasspath "/usr/lib/jvm/java-9-openjdk-amd64/jrt-fs.jar" -source 1.8 -target 1.8 -classpath udf:java_src -d udf -sourcepath java_src \
javac -classpath udf:java_src -d udf -sourcepath java_src \
      java_src/com/exasol/ExaCompilationException.java \
      java_src/com/exasol/ExaConnectionAccessException.java \
      java_src/com/exasol/ExaConnectionInformation.java \
      java_src/com/exasol/ExaDataTypeException.java \
      java_src/com/exasol/ExaImportSpecification.java \
      java_src/com/exasol/ExaExportSpecification.java \
      java_src/com/exasol/ExaIterationException.java \
      java_src/com/exasol/ExaIterator.java \
      java_src/com/exasol/ExaMetadata.java \
      java_src/com/exasol/ExaCompiler.java \
      java_src/com/exasol/ExaConnectionInformationImpl.java \
      java_src/com/exasol/ExaImportSpecificationImpl.java \
      java_src/com/exasol/ExaExportSpecificationImpl.java \
      java_src/com/exasol/ExaIteratorImpl.java \
      java_src/com/exasol/ExaMetadataImpl.java \
      java_src/com/exasol/ExaUndefinedSingleCallException.java \
      java_src/com/exasol/ExaWrapper.java \
      java_src/com/exasol/swig/ConnectionInformationWrapper.java \
      java_src/com/exasol/swig/exascript_java.java \
      java_src/com/exasol/swig/exascript_javaJNI.java \
      java_src/com/exasol/swig/ImportSpecificationWrapper.java \
      java_src/com/exasol/swig/ExportSpecificationWrapper.java \
      java_src/com/exasol/swig/Metadata.java \
      java_src/com/exasol/swig/ResultHandler.java \
      java_src/com/exasol/swig/SWIGTYPE_p_ExecutionGraph__ImportSpecification.java \
      java_src/com/exasol/swig/SWIGTYPE_p_ExecutionGraph__ExportSpecification.java \
      java_src/com/exasol/swig/SWIGVM_datatype_e.java \
      java_src/com/exasol/swig/SWIGVM_itertype_e.java \
      java_src/com/exasol/swig/TableIterator.java \
|| die "Failed to compile java API"
jar -cf udf/exaudf-api-src.jar \
      -C java_src com/exasol/ExaCompilationException.java \
      -C java_src com/exasol/ExaConnectionAccessException.java \
      -C java_src com/exasol/ExaConnectionInformation.java \
      -C java_src com/exasol/ExaDataTypeException.java \
      -C java_src com/exasol/ExaImportSpecification.java \
      -C java_src com/exasol/ExaExportSpecification.java \
      -C java_src com/exasol/ExaIterationException.java \
      -C java_src com/exasol/ExaIterator.java \
      -C java_src com/exasol/ExaMetadata.java \
      LICENSE-exasol-script-api.txt \
|| die "Failed to create exaudf-api-src.jar"
jar -cf udf/exaudf-api.jar \
      -C udf com/exasol/ExaCompilationException.class \
      -C udf com/exasol/ExaConnectionAccessException.class \
      -C udf com/exasol/ExaConnectionInformation.class \
      -C udf com/exasol/ExaConnectionInformation\$ConnectionType.class \
      -C udf com/exasol/ExaDataTypeException.class \
      -C udf com/exasol/ExaImportSpecification.class \
      -C udf com/exasol/ExaExportSpecification.class \
      -C udf com/exasol/ExaIterator.class \
      -C udf com/exasol/ExaIterationException.class \
      -C udf com/exasol/ExaMetadata.class \
      LICENSE-exasol-script-api.txt \
|| die "Failed to create exaudf-api.jar"
jar -cf udf/exaudf.jar \
      -C udf com/exasol/ExaCompilationException.class \
      -C udf com/exasol/ExaConnectionAccessException.class \
      -C udf com/exasol/ExaConnectionInformation.class \
      -C udf com/exasol/ExaConnectionInformation\$ConnectionType.class \
      -C udf com/exasol/ExaDataTypeException.class \
      -C udf com/exasol/ExaImportSpecification.class \
      -C udf com/exasol/ExaExportSpecification.class \
      -C udf com/exasol/ExaIterator.class \
      -C udf com/exasol/ExaIterationException.class \
      -C udf com/exasol/ExaMetadata.class \
      -C udf com/exasol/ExaCompiler.class \
      -C udf com/exasol/ExaCompiler\$JavaSource.class \
      -C udf com/exasol/ExaConnectionInformationImpl.class \
      -C udf com/exasol/ExaImportSpecificationImpl.class \
      -C udf com/exasol/ExaExportSpecificationImpl.class \
      -C udf com/exasol/ExaIteratorImpl.class \
      -C udf com/exasol/ExaMetadataImpl.class \
      -C udf com/exasol/ExaMetadataImpl\$1.class \
      -C udf com/exasol/ExaMetadataImpl\$ColumnInfo.class \
      -C udf com/exasol/ExaUndefinedSingleCallException.class \
      -C udf com/exasol/ExaWrapper.class \
      -C udf com/exasol/swig/exascript_java.class \
      -C udf com/exasol/swig/TableIterator.class \
      -C udf com/exasol/swig/SWIGVM_datatype_e.class \
      -C udf com/exasol/swig/SWIGTYPE_p_ExecutionGraph__ImportSpecification.class \
      -C udf com/exasol/swig/SWIGTYPE_p_ExecutionGraph__ExportSpecification.class \
      -C udf com/exasol/swig/Metadata.class \
      -C udf com/exasol/swig/ResultHandler.class \
      -C udf com/exasol/swig/SWIGVM_itertype_e.class \
      -C udf com/exasol/swig/exascript_javaJNI.class \
      -C udf com/exasol/swig/ConnectionInformationWrapper.class \
      -C udf com/exasol/swig/ImportSpecificationWrapper.class \
      -C udf com/exasol/swig/ExportSpecificationWrapper.class \
|| die "Failed to create exaudf.jar"


fi


# compile exaudfclient
CXXFLAGS="-fPIC $CXXFLAGS"

g++ -o scriptoptionlines.o -c scriptoptionlines.cc $CXXFLAGS || die "Failed to compile scriptoptionlines.o"

if [ ! -z "$CUSTOM_PROTOBUF_PREFIX" ]; then
    CXXFLAGS="-DCUSTOM_PROTOBUF_PREFIX=\"$CUSTOM_PROTOBUF_PREFIX\" $CXXFLAGS"
fi

echo "================================================"
echo "================================================"
echo "= compiling exaudfclient.cc with"
echo "= CXXFLAGS=$CXXFLAGS"
echo "= LDFLAGS=$LDFLAGS"
echo "================================================"
echo "================================================"
echo "================================================"

g++ -o exaudfclient.o -c exaudfclient.cc $CXXFLAGS || die "Failed to compile exaudfclient.o"
g++ -o zmqcontainer.pb.o -c zmqcontainer.pb.cc $CXXFLAGS || die "Failed to compile zmqcontainer.pb.o"

g++ -o scriptDTOWrapper.o -c script_data_transfer_objects_wrapper.cc $CXXFLAGS || die "Failed to compile scriptDTOWrapper.o"
g++ -o scriptDTO.o -c script_data_transfer_objects.cc $CXXFLAGS || die "Failed to compile scriptDTO.o"

g++ -o exaudflib.o -c exaudflib.cc $CXXFLAGS || die "Failed to compile exaudflib.o"

g++ -shared -o $LIBEXAUDF_NAME.so exaudflib.o zmqcontainer.pb.o scriptDTOWrapper.o scriptDTO.o -Wl,--no-as-needed -l zmq



echo "g++ -o $EXECUTABLE_NAME exaudfclient.o $CONTAINER_CLIENT_OBJECT_FILES scriptoptionlines.o -Wl,--no-as-needed scriptDTOWrapper.o scriptDTO.o $LDFLAGS $LIBS"

g++ -o $EXECUTABLE_NAME exaudfclient.o $CONTAINER_CLIENT_OBJECT_FILES scriptoptionlines.o -Wl,--no-as-needed scriptDTOWrapper.o scriptDTO.o $LDFLAGS $LIBS || die "Failed to compile $EXECUTABLE_NAME"


# Create output files
cp -a "$BUILDDIR/$EXECUTABLE_NAME" "$OUTPUTDIR/$EXECUTABLE_NAME" || die "Failed to create $OUTPUTDIR/$EXECUTABLE_NAME"
cp -a "$BUILDDIR/$LIBEXAUDF_NAME.so" "$OUTPUTDIR/$LIBEXAUDF_NAME.so" || die "Failed to create $OUTPUTDIR/$LIBEXAUDF_NAME.so"
chmod +x "$OUTPUTDIR/$EXECUTABLE_NAME" || die "Failed chmod of $OUTPUTDIR/$EXECUTABLE_NAME"

if [ -f pyextdataframe.so ]; then
    cp -a "$BUILDDIR/pyextdataframe.so" "$OUTPUTDIR/pyextdataframe.so" || die "Failed to create $OUTPUTDIR/pyextdataframe.so"
fi

if [ "$RELEASE_SOURCES" = "yes" ]; then
    sources_target="$OUTPUTDIR/src"
    mkdir -p $sources_target
    for SRC in \
        zmqcontainer.proto exaudfclient.cc exaudflib.cc exaudflib.h
    do
	cp "$BUILDDIR/$SRC" "$sources_target/" || die "Failed to copy file $SRC from $BUILDDIR to $sources_target"
    done
fi


if [ "$ENABLE_JAVA_IMPL" = "yes" ]; then
    cp -a "$BUILDDIR/udf/exaudf-api-src.jar" "$OUTPUTDIR/exasol-script-api-sources.jar" || die "Failed to create $OUTPUTDIR/exasol-script-api-sources.jar"
    cp -a "$BUILDDIR/udf/exaudf-api.jar" "$OUTPUTDIR/exasol-script-api.jar" || die "Failed to create $OUTPUTDIR/exasol-script-api.jar"
    cp -a "$BUILDDIR/udf/exaudf.jar" "$OUTPUTDIR/exaudf.jar" || die "Failed to create $OUTPUTDIR/exaudf.jar"
fi

