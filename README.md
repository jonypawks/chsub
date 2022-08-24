# chsub

Change the subsystem of a PE executable between console and windows applications.

## Installation

`chsub` is available in the `haxelib` repository and can be installed with `haxelib install chsub`.

## Usage

```
haxelib run chsub [windows|console] EXE_FILE
```

So to change a console application to a windows application:

```
$ haxelib run chsub windows ./path/to/app.exe
```

And then to reverse the changes:

```
$ haxelib run chsub console ./path/to/app.exe
```