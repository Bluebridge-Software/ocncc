BEGIN {
	nsamples=0
        dfile="clientLog_data.csv"
        hfile="clientLog_hdrs.csv"
        printf "" > dfile
}

{
	if ( $9 == "ALL" ) {
		nsamples++
		printf "%d, %d, %d, %d",nsamples,$14,$16,$18 >> dfile
		printf "\n" >> dfile
	}
}

END {
	printf "sample, min, avg, max\n" >> hfile
}
