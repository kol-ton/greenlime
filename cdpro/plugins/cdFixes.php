<?php
function DailyMotion_preParse(&$page, $URL, $proxy) {
    if(preg_match('/video\/([^_]+)/', $URL, $matches)) { //Check if DailyMotion URL is a video
        $html = $proxy->curlRequest("http://www.dailymotion.com/embed/video/".$matches[1])["page"]; //Get basic embed video source

        if(preg_match_all('#type":"video\\\/mp4","url":"([^"]+)"#is', $html, $matches) && !$proxy->stripObjects) {
            $url = stripslashes(end($matches[1])); //Find the best available video source

            //Build and insert basic video element into page which users can watch
            $randPlayerID = substr(md5(rand(0,500)),0,10);
            $html = '<video style="width:100%;height:100%;" autoplay controls id="'.$randPlayerID.'"><source type="video/mp4" src="'.$url.'"></video>';
            $page = preg_replace('#<div class="player-container">.*?</div>#s', '<div class="player_container" style="width:880px; height:495px;">'.$html.'</div>', $page, 1);
        }
    }
}

function YouTube_preRequest($page, $URL, $proxy) {
	$cookies = file_get_contents($proxy->cookieDIR); $m = preg_grep("~^(\.youtube.*PREF.*f1\=[0-9]+)$~i",explode(PHP_EOL,$cookies));
    if (!empty($m)) { $m = reset($m); file_put_contents($proxy->cookieDIR,str_replace($m,$m."&f6=8008&f5=30",$cookies)); }  else { file_put_contents($proxy->cookieDIR,$cookies."\n.youtube.com	TRUE	/	FALSE	1539395795	PREF	f1=50000000"); }

    //Add query string to migrate any mobile users to desktop app
    if (preg_match("/\/m.youtube.[a-zA-z]+/i", $URL)) {
        parse_str(parse_url($URL,PHP_URL_QUERY), $queries);
        $queries = array_merge($queries, array("app" => "desktop", "persist_app" => "1", "noapp" => "1"));
        $proxy->setURL(explode("?",preg_replace("/m.youtube/i","youtube",$URL,1))[0]."?".http_build_query($queries));
    }
}

function YouTube_preParse(&$page, $URL, $proxy) {
    if (preg_match('@url_encoded_fmt_stream_map["\']:\s*["\']([^"\'\s]*)@', $page, $encodedStreamMap) && !$proxy->stripObjects) {
        $encodedStreamMap[1] = preg_replace_callback('/\\\\u([0-9a-f]{4})/i', (function ($match) { return mb_convert_encoding(pack('H*', $match[1]), 'UTF-8', 'UCS-2BE'); }), $encodedStreamMap[1]);
        $decodedMaps = explode(',', $encodedStreamMap[1]); //Find all video URLs

        foreach($decodedMaps as $map) {
            $url = $type = ''; parse_str($map); //Parse values in stream maps
            if (strpos($type,"x-flv")===false) { //See if video is supported by player
                $randPlayerID = substr(md5(rand(0,500)),0,10);
                $html = '<video style="width:100%;height:100%;" autoplay controls id="'.$randPlayerID.'"><source type="'.explode(";",$type)[0].'" src="'.$url.'"></source></video>';
                $page = preg_replace('#<div id="player-api"([^>]*)>.*<div class="clear"#s', '<div id="player-api"$1>'.$html.'</div></div><div class="clear"', $page, 1);
                break; //Video added to screen, exit out of loop now
            }
        }
    }

    $page = str_replace(array("a=Ba().contentWindow.history.pushState,\"function\"==typeof a","\"function\"==typeof c"),"false",$page);
}

if (class_exists("censorDodge")) { //Check that the class is accessible to add the function hooks
    censorDodge::addAction("DailyMotion_preParse","preParse","#dailymotion.[a-zA-z.]+#i");
    censorDodge::addAction("YouTube_preRequest","preRequest","#youtube.[a-zA-z.]+#i");
    censorDodge::addAction("YouTube_preParse","preParse","#youtube.[a-zA-z.]+#i");
}
