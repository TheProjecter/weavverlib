;//--------------------------------------------------------------------------------------------
; Defines
     Name Photon

     !addplugindir ".\Plugins"

     !define VERSION 0.1
     !define REGKEY "SOFTWARE\$(^COMPANY)\$(^Name)"
     !define COMPANY "Weavver"
     !define URL www.weavver.com
     !define DOTNET_VERSION "2.0.50727"
;//--------------------------------------------------------------------------------------------
; Included files
     !include Sections.nsh
     !include LogicLib.nsh
     !include Library.nsh
;Function ShowCustom
;//--------------------------------------------------------------------------------------------
; Installer attributes
     CRCCheck on
     InstallDir $TEMP
     OutFile PhotonInstall.exe
     ShowInstDetails hide
     VIProductVersion ${VERSION}
     VIAddVersionKey ProductName $(^Name)
     VIAddVersionKey ProductVersion "${VERSION}"
     VIAddVersionKey CompanyName "${COMPANY}"
     VIAddVersionKey CompanyWebsite "${URL}"
     VIAddVersionKey FileVersion "${VERSION}"
     VIAddVersionKey FileDescription ""
     VIAddVersionKey LegalCopyright "&copy; 2008 ${COMPANY}"
;//--------------------------------------------------------------------------------------------
     Function .onInit
         SetOverwrite on
         SetOutPath $INSTDIR
         File $(^Name).exe
         Exec $INSTDIR\$(^Name).exe
         SetSilent silent
     FunctionEnd
;//--------------------------------------------------------------------------------------------
     Section
     SectionEnd
;//--------------------------------------------------------------------------------------------
     Function un.onInit
     FunctionEnd
;//--------------------------------------------------------------------------------------------
     Function un.onUninstSuccess
     FunctionEnd
;//--------------------------------------------------------------------------------------------