BEGIN {
	nsamples=0
	dfile="iostat_detail_data.csv"
	hfile="iostat_detail_hdrs.csv"
	sfile="iostat_summary.txt"
	printf "" > dfile 
	printf "" > sfile
}

{
	if ( $1 == "r/s" ) {
		if ( nsamples > 0 ) {
			printf "%d",nsamples >> dfile
			for ( dev in adev ) {
				printf ",%0.1f",akws[dev] >> dfile
				akwsTotal[dev]=akwsTotal[dev]+akws[dev]
			}
			printf ",%d",nsamples >> dfile
			for ( dev in adev ) {
				printf ",%0.1f",asvct[dev] >> dfile
				ascvtTotal[dev]=asvctTotal[dev]+asvct[dev]
			}
			printf ",%d",nsamples >> dfile
			for ( dev in adev ) {
				printf ",%d",abusy[dev] >> dfile
				abusyTotal[dev]=abusyTotal[dev]+abusy[dev]
			}
			printf "\n" >> dfile
		}
		nsamples++
	}

	else if ( $1 == "extended" ) { }

	else {
		if ( $11 in adev ) {
			akws[$11]=$4
			asvct[$11]=$8
			abusy[$11]=$10
		}
		else {
			adev[$11]=$11
			if ( NF > 11 )
				adev2[$11]=$12
			else
				adev2[$11]=""
			akws[$11]=$4
			asvct[$11]=$8
			abusy[$11]=$10
		}
	}
}

END {
        printf "sample" > hfile
	for ( dev in adev ) {
		name = dev adev2[dev]
		gsub(/,/, ".", name)
		printf ",%s kw/s",name >> hfile  
	}
        printf ",sample" >> hfile
	for ( dev in adev ) {
		name = dev adev2[dev]
		gsub(/,/, ".", name)
		printf ",%s svc_t",name >> hfile  
	}
        printf ",sample" >> hfile
	for ( dev in adev ) {
		name = dev adev2[dev]
		gsub(/,/, ".", name)
		printf ",%s busy",name >> hfile  
	}
    printf "\n" >> hfile
        
    printf "Disk usage summary \n" >> sfile
    printf "================== \n" >> sfile
    printf "\n" >> sfile
    Disk="Disk"
    avkws="Avg kw/s"
    avsvct="Avg svc_t"
    avpbusy="Avg % busy"
    printf " %-41s %-10s %-10s %-10s \n",Disk,avkws,avsvct,avpbusy >> sfile
    for ( dev in adev ) {
      if (akwsTotal[dev] > 0 || ascvtTotal[dev] > 0 || abusyTotal[dev] > 0 ) {
        name = dev adev2[dev]
        gsub(/,/, ".", name)
        printf " %-41s %-10.1f %-10.1f %-10.1f \n",name,akwsTotal[dev]/nsamples,ascvtTotal[dev]/nsamples,abusyTotal[dev]/nsamples >> sfile
      }
    }
    printf "\n\n" >> sfile
}

