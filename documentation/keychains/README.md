This is a set of file of creating keychains of the AppArmor
logo. There are multiple variants of the keychain, and for a given
variant it may have multiple files to support different programs or
uses. If the base name of the file is the same then the files are just
different format variants of the same file.

Eg.
- AppArmorLogoShadowFlat.3mf
- AppArmorLogoShadowFlat.FCStd
- AppArmorLogShadowFlat.obj

are all variants of the AppArmor keychain that embedds a shadow.


3D Printing Files
.FCStd - Free Cad model file

.3mf - 3d manufacturing format. Contains model and material/color
       information.
.obj - 3d object format, general higher quality than .stl
.stl - sterio lithograthy file


Laser Cutting/Engraving Files
.lighburn - lightburn layout file, includes the model
.svg - scalable vector graphics file



# Key Chain Descriptions

Overview of Naming
Flat - backside flat
FlatFlat - backside and front flat
Shadow - a shadow element has been incorporated. Relies on translucency
         to be shown.

## 3D Printed key chains

### Filament swap/tool changer 3D printer

#### AppArmorLogoFlat
- variant of the key chain with the backside flat, designed to easily 3D
  printed with a filament swapping 3d printer

#### AppAromrLogoShadowFlat
- variant of the key chain with the backside flat, and a shadow element
  that is done using a black/dark layer internally and relies on the
  translucency of filament for the shadow effect to appear. Designed to
  be easily 3D printed with a filament swapping 3D printer.

### Single Filament 3D printer prints

Single Filament models are designed to be printed in single color
parts and assembled afterwards. They share a lot in common with the
laser cut files, but have been extruded into 3d parts.

Some tuning of filament settings will be needed to get these models to
assemble correctly. The use of an assembly jib is recommended.

#### todo

#### AssemblyJig-D1,D2
- an assembly jig to help with multiple part print or laser cut keychains.
  The X, and Y specify the expect depths of different elements that are
  assembled together to make the keychain and are responsible for the
  raised effects.


## Laser Cut key chains


# Assemblying

For non-flat models an assembly jig is recommended. It will help with the
alignment of the various elements of the model.

