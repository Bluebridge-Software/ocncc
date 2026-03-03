BEGIN {
	npids=0
	nsamples=0
	dfile="prstat_detail_data.csv"
	hfile="prstat_detail_hdrs.csv"
	sfile="prstat_summary.txt"
	printf "" > dfile 
	printf "" > sfile
}

{
	if ( $1 == "PID" ) {
		nsamples++
	}

	else if ( $1 == "Total:" ) {
		printf "%d",nsamples >> dfile
		for (i = 1; i <= npids; i++) {
			pid=apidmap[i]
			pidUsage=100.0-aslp[pid]
			pidTotal[pid]=pidTotal[pid]+pidUsage
			printf ",%0.1f",100.0-aslp[pid] >> dfile
			aslp[pid]=100.0
		}
		printf "\n" >> dfile
	}

	else {
		if ( $1 in apid ) {
			aslp[$1]=$9
		}
		else {
			npids++
			apidmap[npids]=$1
			apid[$1]=$1
			aname[$1]=$15
			aslp[$1]=$9
		}
	}
}

END {
    printf "sample" > hfile
    for (i = 1; i <= npids; i++) {
        	pid=apidmap[i]
		if ( aname[pid] ~ /oracle/ ) {
			p=" "
			while ( getline <"oracle_ptree.log" > 0 ) {
				if ( $1 == pid && $0 ~ "^[ \t]+") {
					numTkn = split(p, arr, "/");
					aname[pid]=aname[pid] "-" arr[numTkn]
				} else if ( $1 == pid ) {
				    aname[pid]=aname[pid] "-" $2
			 	}
				p=$2
			}
			close "oracle_ptree.log"
		} 
    	printf ",%s(%d)",aname[pid],pid >> hfile
	}
    printf "\n" >> hfile
    
    printf "Process average load summary \n" >> sfile
    printf "============================ \n" >> sfile
    printf "\n" >> sfile
    for (i = 1; i <= npids; i++) {
      pid=apidmap[i]
      if ( pidTotal[pid]/nsamples >= 1 ) {
        printf " %-40s %-8.2f \n",aname[pid],pidTotal[pid]/nsamples >> sfile
      }
    }  
    printf "\n\n" >> sfile
}
