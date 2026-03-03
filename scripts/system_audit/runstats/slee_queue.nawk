BEGIN {
	nsamples=0
        bgotrecord=0
	dfile="slee_queue_data.csv"
	hfile="slee_queue_hdrs.csv"
	sfile="slee_queue_summary.txt"
	printf "" > dfile
	printf "" > sfile 
}

{
	if ( NF == 0 && bgotrecord == 1 ) {
		if ( nsamples > 0 ) {
			printf "%d",nsamples >> dfile
		for ( name in aname ) {
			printf ",%d",aqueue[name] >> dfile
		}
		printf "\n" >> dfile

		}
		nsamples++
		bgotrecord=0
	}

	else if ( NF == 7 ) {

        	if ( $2 == "Name" ) { }

		else {
			if ( $2 in aname ) {
				aqueue[$2]=$5
				if ( $5 > 0 ) {
				    if ($5 < amin[$2] ) {
				        amin[$2] = $5
				    }
				    if ($5 > amax[$2] ) {
				        amax[$2] = $5
				    }
				    atotal[$2]=atotal[$2]+$5
			    }
			}
			else {
				aname[$2]=$2
				aqueue[$2]=$5
				if ($5 > 0) {
				    amin[$2]=999999999999
				    amax[$2]=$5
				    atotal[$2]=$5
				}
			}
			bgotrecord=1
		}
	}
}

END {
        printf "sample" > hfile
	for ( name in aname ) {
		printf ",%s",name >> hfile  
	}
    printf "\n" >> hfile
    
    printf "SLEE Queue size summary\n" >> sfile
    printf "=======================\n" >> sfile
    printf "\n" >> sfile
    printf " Process              Min        Max        Avg \n" >> sfile 
    for ( name in aname ) {
        printf " %-20s %-10d %-10d %-10d \n",name,amin[name],amax[name],atotal[name]/nsamples >> sfile
    }
    printf "\n\n" >> sfile
}

