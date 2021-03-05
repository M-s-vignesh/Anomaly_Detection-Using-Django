from django import forms

class data_form(forms.Form):
	 text1= forms.IntegerField(label="Total Number Of data packs received")
	 text2= forms.IntegerField(label="Total Anomalies Detected")
	 text3= forms.IntegerField(label="Total Anomalies Blocked")
	 text4= forms.IntegerField(label="Total Number Of good packets passed through firewall")