## Example SDMX data
A sample dataset is provided for Central Bank Policy [WS_CBPOL](WS_CBPOL.xml).

XSD schemas are included together with a bash script [validate.sh](validate.sh) to perform schema validation on the WS_CBPOL.xml data. The script requires the `xmllint` tool.

SDMX REST data API queries to retrieve other sample datasets are provided in [example_data/dataqueries.md](example_data/dataqueries.md).

## Choice of SDMX data format for the PoC
The SDMX standard provides several different formats for serialising data. For the purposes of the blockchain project, 'SDMX-ML 2.1 structure specific' is recommended since it's the most widely used. This is XML with the schema specific to the DSD. Thus, to confirm a data message is 'XML schema valid', two sets of XSD schemas are required:
- SDMX-ML 2.1 generic schemas available on https://xml.sdmx.org; and
- The structure specific schema which must be generated from the SDMX structural metadata by an appropriate tool such as Fusion Metadata Registry, for instance https://registry.sdmx.io/webservice/schema.html

## Adding attestations to an SDMX XML data message
Attestations inclusing hashes, digital signatures etc as appropriate could be published separately, but might be better embedded in the XML data message. A good place is the `<Header>` element that carries general metadata about the dataset including when it was prepared and the data structure to which it relates. It can optionally carry one or more `<Source>` elements that are of the simple `xsi:string` data type, have no length constraints and can be used for any purpose.

Here's a truncated example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<message:StructureSpecificData 
  xmlns:ss="http://www.sdmx.org/resources/sdmxml/schemas/v2_1/data/structurespecific" 
  xmlns:footer="http://www.sdmx.org/resources/sdmxml/schemas/v2_1/message/footer" 
  xmlns:ns1="urn:sdmx:org.sdmx.infomodel.datastructure.Dataflow=BIS:WS_CBPOL(1.0):ObsLevelDim:TIME_PERIOD" 
  xmlns:message="http://www.sdmx.org/resources/sdmxml/schemas/v2_1/message" 
  xmlns:common="http://www.sdmx.org/resources/sdmxml/schemas/v2_1/common" 
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" >
  <message:Header>
    <message:ID>IDREFf3e3c3e2-4de0-410f-bc02-0b4b4a5723ad</message:ID>
    <message:Test>false</message:Test>
    <message:Prepared>2025-07-31T11:36:52Z</message:Prepared>
    <message:Sender id="UNKNOWN"/>
    <message:Receiver id="guest"/>
    <message:Structure structureID="BIS_WS_CBPOL_1_0" namespace="urn:sdmx:org.sdmx.infomodel.datastructure.Dataflow=BIS:WS_CBPOL(1.0):ObsLevelDim:TIME_PERIOD" dimensionAtObservation="TIME_PERIOD">
      <common:StructureUsage>
        <Ref agencyID="BIS" id="WS_CBPOL" version="1.0"/>
      </common:StructureUsage>
    </message:Structure>
    <message:DataSetAction>Information</message:DataSetAction>
    <message:DataSetID>0efcb1b9-bfb2-4581-b993-058668c04cd2</message:DataSetID>
    <message:Extracted>2025-07-31T11:36:52</message:Extracted>
    <message:ReportingBegin>1945-01-01T00:00:00</message:ReportingBegin>
    <message:ReportingEnd>2025-06-01T23:59:59</message:ReportingEnd>
    <message:Source>Here we can put our attestations - the type is xs:string</message:Source>
    <message:Source>A controlled vocabulary could be used to distinguish a format blockchain backed proof from other information that people may use the Source for, e.g. the name of the tool used to generate the message</message:Source>
    <message:Source>We can have multiple Source elements if needed for the provenance, and these can co-exist with Source elements for other purposes.</message:Source>
  </message:Header>
  <message:DataSet UNIT_MULT="0" UNIT_MEASURE="368" ss:dataScope="DataStructure" xsi:type="ns1:DataSetType" ss:structureRef="BIS_WS_CBPOL_1_0">
    <Series FREQ="M" REF_AREA="NL" SOURCE_REF="De Nederlandsche Bank, Bank for International Settlements" COMPILATION="From 1 Jan 1999 onwards: the series is discontinued as Netherlands joined the euro area; prior to 31 Dec 1998: the main interest policy rate corresponds to the fixed advance rate set by the De Nederlandsche Bank (DNB)." DECIMALS="4" TITLE=" Central bank policy rates - Netherlands - Monthly - End of period">
      <Obs TIME_PERIOD="1945-01" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
      <Obs TIME_PERIOD="1945-02" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
      <Obs TIME_PERIOD="1945-03" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
      <Obs TIME_PERIOD="1945-04" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
      <Obs TIME_PERIOD="1945-05" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
      <Obs TIME_PERIOD="1945-06" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
      <Obs TIME_PERIOD="1945-07" OBS_VALUE="3.5" OBS_STATUS="A" OBS_CONF="F"/>
```

## Distinguishing embedded attestations from other <source> metadata
As the system that generates the data message may want to add `<Source>` elements for it's own purposes, we need to be able to distinguish between those that carry attestation information, and others that should be ignored by apps attempting to verify the data's provenance and authenticity. 

For this, a controlled vocabulary or some distibuishing label could be used. For instance:
```xml
<message:Source>SDMXBLOCKCHAIN:SHA:3bd970e72cceeac131ad2fbb37740de74a796780</message:Source>
```

